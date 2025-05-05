import boto3
import botocore
import json
import random
import string
import sys

iam = boto3.client('iam')

aws_services = {
    "EC2": "AmazonEC2",
    "S3 bucket": "AmazonS3",
    "RDS": "AmazonRDS",
    "LAMBDA": "AWSLambda",
    "ECR": "AmazonEC2ContainerRegistry",
    "Cloud Watch": "CloudWatch",
    "Cloud Front": "CloudFront",
    "AWS amplify": "AWSAmplify",
    "AWS bedrocks": "Bedrock"
}

access_levels = {
    "Read": "ReadOnlyAccess",
    "Full": "FullAccess"
}

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def user_exists(username):
    try:
        iam.get_user(UserName=username)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return False
        raise e

def list_user_policies(username):
    print(f"\n✅ IAM User '{username}' already exists.\n\n📌 Attached Managed Policies:")
    managed = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    if managed:
        for policy in managed:
            print(f"- {policy['PolicyName']} ({policy['PolicyArn']})")
    else:
        print("- None")

    print("\n📌 Inline Policies:")
    inline = iam.list_user_policies(UserName=username)['PolicyNames']
    if inline:
        for policy in inline:
            print(f"- {policy}")
    else:
        print("- None")

def create_user(username):
    iam.create_user(UserName=username)

def delete_user(username):
    try:
        policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in policies:
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])

        inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
        for name in inline_policies:
            iam.delete_user_policy(UserName=username, PolicyName=name)

        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

        try:
            iam.delete_login_profile(UserName=username)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise e

        iam.delete_user(UserName=username)
        print(f"🧹 Rolled back and deleted user '{username}' due to error.")
    except Exception as e:
        print(f"⚠️ Error cleaning up user '{username}': {e}")

def create_access_key(username):
    keys = iam.create_access_key(UserName=username)['AccessKey']
    return keys['AccessKeyId'], keys['SecretAccessKey']

def create_login_profile(username):
    password = generate_random_password()
    iam.create_login_profile(UserName=username, Password=password, PasswordResetRequired=False)
    return password

def store_credentials(username, content):
    with open(f"./Credential-Folder/{username}.txt", "w") as f:
        f.write(content)

def attach_policy(username, policy_arn):
    iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)

def put_inline_region_restrict_policy(username, region):
    policy_name = "RegionRestriction"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": region
                    }
                }
            }
        ]
    }
    iam.put_user_policy(
        UserName=username,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document)
    )

def get_account_id():
    sts = boto3.client('sts')
    return sts.get_caller_identity()["Account"]

def create_custom_write_policy(service_name):
    policy_name = f"{service_name}WriteOnly"
    account_id = get_account_id()
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    try:
        existing = iam.get_policy(PolicyArn=policy_arn)
        return existing['Policy']['Arn']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise e

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                f"{service_name.lower()}:Put*",
                f"{service_name.lower()}:Create*",
                f"{service_name.lower()}:Upload*"
            ],
            "Resource": "*"
        }]
    }

    response = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document)
    )
    return response['Policy']['Arn']

def main():
    username = input(">> Enter IAM username to create: ")

    if user_exists(username):
        list_user_policies(username)
        return

    try:
        create_user(username)
        print("✅ User created successfully.")

        choice = input(">> Do you want \n1.Access Key and Secret Key \n2.Login password?\n>> Enter 1 or 2: ")

        creds = f"Username: {username}\n"

        if choice == "1":
            access_key, secret_key = create_access_key(username)
            creds += f"Access Key: {access_key}\nSecret Key: {secret_key}\n"
        else:
            password = create_login_profile(username)
            attach_policy(username, "arn:aws:iam::aws:policy/IAMUserChangePassword")
            creds += f"Login password: {password} \nLogin link: https://{get_account_id()}.signin.aws.amazon.com/console\n"

        region = input(">> Enter AWS region to allow user to operate in: ")
        creds += f"Region: {region}\n"
        put_inline_region_restrict_policy(username, region)

        services_added = []
        
        for i, service in enumerate(aws_services.keys(), 1):
            print(f"{i}. {service}")

        while True:
            print("\nSelect AWS Service from this list:")
            # for i, service in enumerate(aws_services.keys(), 1):
            #     print(f"{i}. {service}")
            choice = int(input(f">> Enter choice number between (1-{len(aws_services)}): "))
            if choice < 1 or choice > len(aws_services):
                print("Invalid choice. Please try again....")
                continue
            service_name = list(aws_services.keys())[choice - 1]
            service_prefix = aws_services[service_name]

            access = input(f">> Enter access level on {service_name} (Read / Write / Full): ").capitalize()

            if access in access_levels:
                policy_arn = f"arn:aws:iam::aws:policy/{service_prefix}{access_levels[access]}"
            elif access == "Write":
                try:
                    policy_arn = create_custom_write_policy(service_prefix)
                    print(f"✅ Custom WriteOnly policy assigned: {policy_arn}")
                except Exception as e:
                    print(f"❌ Failed to create or assign write-only policy: {e}")
                    continue
            else:
                print("Invalid access type. Skipping...")
                continue

            attach_policy(username, policy_arn)
            services_added.append(f"{service_name} ({access})")

            more = input(">> Do you want to add another service? (yes/no): ").strip().lower()
            if more != "yes":
                break
            

        creds += "\nServices Granted:\n"
        creds += "\n".join(services_added)
        store_credentials(username, creds)
        print(f"\n✅ Details stored in ./Credential-Folder/{username}.txt")

    except Exception as e:
        print(f"❌ Error occurred: {e}")
        delete_user(username)

if __name__ == "__main__":
    main()