import boto3
import json

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

def create_custom_write_policy(service, region):
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

def remove_current_policies(iam, username, service):
    attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for policy in attached_policies:
        if service in policy['PolicyName'].lower():
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])
            print(f"Detached policy: {policy['PolicyName']}")

def check_user_exists(iam, username):
    try:
        iam.get_user(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False

def change_permission(username, service, new_access_level, region):
    iam = boto3.client('iam')

    # Check if the user exists
    if not check_user_exists(iam, username):
        print(f"❌ User '{username}' does not exist.")
        return

    # Remove the current policy for the service (ec2 or s3)
    remove_current_policies(iam, username, service)

    if new_access_level == "write":
        # Create custom write policy if it doesn't exist
        policy_doc = create_custom_write_policy(service, region)
        iam.put_user_policy(UserName=username, PolicyName=f"Custom{service.upper()}WriteOnly", PolicyDocument=json.dumps(policy_doc))
        print(f"✅ Custom {service.upper()} write-only policy with region restriction attached.")
    else:
        # Attach the AWS-managed policy for read or full access
        arn = get_policy_arn(service, new_access_level)
        if arn:
            iam.attach_user_policy(UserName=username, PolicyArn=arn)
            print(f"✅ AWS-managed {service.upper()} {new_access_level.upper()} policy attached.")
        else:
            print(f"❌ Invalid access level for {service.upper()}.")

def main():
    username = input("Enter the IAM username to change permissions: ").strip()
    service = input("Which service do you want to change permissions for? (ec2/s3): ").strip().lower()
    new_access_level = input(f"Select new access level for {service.upper()} (read/write/full): ").strip().lower()
    region = input("Enter the region (e.g., us-east-1) for the policy: ").strip()

    try :
        if service not in ["ec2", "s3"]:
            print("❌ Invalid service. Please choose 'ec2' or 's3'.")
            return
        if new_access_level not in ["read", "write", "full"]:
            print("❌ Invalid access level. Please choose 'read', 'write', or 'full'.")
            return

        change_permission(username, service, new_access_level, region)
    except Exception as e:
        print(f"❌ An error occurred: {e}")
        return

    # Change the permission
    

if __name__ == "__main__":
    main()
