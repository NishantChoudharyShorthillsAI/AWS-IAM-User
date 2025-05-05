import boto3
import json
import os

def get_policy_arn(service, access_level):
    policy_map = {
        "ec2": {
            "read": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
            "full": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        },
        "s3": {
            "read": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "full": "arn:aws:iam::aws:policy/AmazonS3FullAccess"
        }
    }
    return policy_map[service].get(access_level, None)

def create_write_only_policy(service, region):
    if service == "ec2":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "ec2:StartInstances",
                    "ec2:StopInstances",
                    "ec2:RebootInstances",
                    "ec2:TerminateInstances",
                    "ec2:CreateTags",
                    "ec2:ModifyInstanceAttribute",
                    "ec2:RunInstances"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": region
                    }
                }
            }]
        }
    elif service == "s3":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:PutObjectAcl",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket"
                ],
                "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"],
                "Condition": {
                    "StringEquals": {
                        "s3:LocationConstraint": region
                    }
                }
            }]
        }

def save_credentials(email, access_key_id, secret_access_key):
    filename = f"{email}.txt"
    with open(filename, "w") as f:
        f.write(f"Email: {email}\n")
        f.write(f"Access Key ID: {access_key_id}\n")
        f.write(f"Secret Access Key: {secret_access_key}\n")
    print(f"\n🔐 Credentials saved to file: {filename}")

def main():
    iam = boto3.client('iam')

    email = input("Enter user's email ID (used as IAM username): ").strip()
    show_keys = input("Do you want to show Access Key and Secret Key? (yes/no): ").strip().lower()
    region = input("Enter AWS region: ").strip()
    resource_choice = input("Which resource to assign? (EC2/S3/Both): ").strip().lower()

    # Create IAM user
    try:
        iam.create_user(UserName=email)
        print(f"IAM user '{email}' created.")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"User '{email}' already exists.")

    # Access key
    keys = iam.create_access_key(UserName=email)['AccessKey']
    if show_keys == "yes":
        print(f"Access Key: {keys['AccessKeyId']}")
        print(f"Secret Key: {keys['SecretAccessKey']}")
    save_credentials(email, keys['AccessKeyId'], keys['SecretAccessKey'])

    def handle_policy(service):
        access = input(f"Select {service.upper()} access level (read/write/full): ").strip().lower()
        if access == "write":
            policy_doc = create_write_only_policy(service, region)
            iam.put_user_policy(UserName=email, PolicyName=f"Custom{service.upper()}WriteOnly", PolicyDocument=json.dumps(policy_doc))
            print(f"✅ Custom {service.upper()} write-only policy with region restriction attached.")
        elif access in ["read", "full"]:
            arn = get_policy_arn(service, access)
            iam.attach_user_policy(UserName=email, PolicyArn=arn)
            print(f"✅ AWS-managed {service.upper()} {access.upper()} policy attached.")
        else:
            print(f"❌ Invalid access level for {service.upper()}.")

    if resource_choice in ["ec2", "both"]:
        handle_policy("ec2")

    if resource_choice in ["s3", "both"]:
        handle_policy("s3")

    print("\n🎉 IAM user setup complete.")

if __name__ == "__main__":
    main()
