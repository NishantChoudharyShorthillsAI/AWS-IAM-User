import boto3
import botocore
import json
import os
from datetime import datetime

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

def user_exists(username):
    try:
        iam.get_user(UserName=username)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return False
        raise e

def list_user_policies(username):
    managed = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    return managed

def detach_all_service_policies(username, service_prefix):
    policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for policy in policies:
        if service_prefix in policy['PolicyName']:
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])

def attach_policy(username, policy_arn):
    iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)

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



def update_user_txt(username):
    policies = list_user_policies(username)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"\n\nChange Permission - {timestamp}"]
    lines.append("Services Granted:")
    for policy in policies:
        policy_name = policy['PolicyName']
        for k, v in aws_services.items():
            if v in policy_name:
                if "ReadOnly" in policy_name:
                    level = "Read"
                elif "FullAccess" in policy_name:
                    level = "Full"
                elif "WriteOnly" in policy_name:
                    level = "Write"
                else:
                    level = "Custom"
                lines.append(f"{k} ({level})")
                break

    os.makedirs("Credential-Folder", exist_ok=True)
    with open(f"./Credential-Folder/{username}.txt", "a") as f:
        f.write("\n".join(lines))

def main():
    username = input(">> Enter IAM username to update: ")

    if not user_exists(username):
        print("❌ User does not exist.")
        return

    policies = list_user_policies(username)
    print(f"\n📌 Policies attached to {username}:")
    service_map = {}
    for i, policy in enumerate(policies, 1):
        policy_name = policy['PolicyName']
        for k, v in aws_services.items():
            if v in policy_name:
                if "ReadOnly" in policy_name:
                    access = "Read"
                elif "FullAccess" in policy_name:
                    access = "Full"
                elif "WriteOnly" in policy_name:
                    access = "Write"
                else:
                    access = "Custom"
                service_map[k] = (v, access)
                print(f"{i}. {k} ({access})")

    while True:
        if not service_map:
            print("No services assigned to user.")
            break

        service_to_change = input("\n>> Enter the name of the service to change access: ").strip()
        if service_to_change not in service_map:
            print("Invalid service name.")
            continue

        new_access = input(">> Enter new access level (Read / Write / Full): ").capitalize()
        service_prefix, _ = service_map[service_to_change]

        detach_all_service_policies(username, service_prefix)

        if new_access in access_levels:
            policy_arn = f"arn:aws:iam::aws:policy/{service_prefix}{access_levels[new_access]}"
        elif new_access == "Write":
            policy_arn = create_custom_write_policy(service_prefix)
        else:
            print("Invalid access level. Skipping.")
            continue

        attach_policy(username, policy_arn)
        print(f"✅ Updated access for {service_to_change} to {new_access}.")

        more = input("\n>> Do you want to update access of another service? (yes/no): ").lower()
        if more != "yes":
            break

    while True:
        add_new = input(">> Do you want to add a new service? (yes/no): ").lower()
        if add_new != "yes":
            break

        print("\nAvailable Services:")
        for i, svc in enumerate(aws_services.keys(), 1):
            print(f"{i}. {svc}")
        try:
            choice = int(input(">> Enter choice number: "))
            service_name = list(aws_services.keys())[choice - 1]
            if service_name in service_map:
                print("Service already assigned. Use update instead.")
                continue
        except (ValueError, IndexError):
            print("Invalid choice. Please try again.")
            continue
        try:
            access = input(">> Enter access level (Read / Write / Full): ").capitalize()
            service_prefix = aws_services[service_name]

            if access in access_levels:
                policy_arn = f"arn:aws:iam::aws:policy/{service_prefix}{access_levels[access]}"
            elif access == "Write":
                policy_arn = create_custom_write_policy(service_prefix)
            else:
                print("Invalid access. Skipping.")
                continue

            attach_policy(username, policy_arn)
            print(f"✅ Added new service {service_name} with {access} access.")
        except Exception as e:
            print(f"❌ Error adding service: {e}")

    update_user_txt(username)
    print(f"\n✅ Updated ./Credential-Folder/{username}.txt with new permissions.")
    
    policies = list_user_policies(username)
    print(f"\n📌 Policies attached to {username}:")
    for i, policy in enumerate(policies, 1):
        policy_name = policy['PolicyName']
        for k, v in aws_services.items():
            if v in policy_name:
                if "ReadOnly" in policy_name:
                    access = "Read"
                elif "FullAccess" in policy_name:
                    access = "Full"
                elif "WriteOnly" in policy_name:
                    access = "Write"
                else:
                    access = "Custom"
                print(f"{i}. {k} ({access})")

if __name__ == "__main__":
    main()
