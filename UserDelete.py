import boto3
import botocore
import os

def delete_user(username):
    iam = boto3.client('iam')

    try:
        # List and delete access keys
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])
            print(f"Deleted access key: {key['AccessKeyId']}")

        # Delete login profile if exists
        try:
            iam.delete_login_profile(UserName=username)
            print(f"Deleted login profile for user: {username}")
        except iam.exceptions.NoSuchEntityException:
            pass  # User had no console login

        # Detach managed policies
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in attached_policies:
            iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])
            print(f"Detached policy: {policy['PolicyName']}")

        # Delete inline policies
        inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
        for policy_name in inline_policies:
            iam.delete_user_policy(UserName=username, PolicyName=policy_name)
            print(f"Deleted inline policy: {policy_name}")

        # Finally, delete user
        iam.delete_user(UserName=username)
        print(f"✅ IAM user '{username}' has been deleted successfully.")

        # Delete associated .txt file if it exists
        file_path = f"./Credential-Folder/{username}.txt"
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"🗑️ Deleted file: {file_path}")
        else:
            print(f"ℹ️ No file named '{file_path}' found.")

    except iam.exceptions.NoSuchEntityException:
        print(f"❌ User '{username}' does not exist.")
    except botocore.exceptions.ClientError as error:
        print(f"❌ Error: {error.response['Error']['Message']}")

def main():
    email = input(">> Enter the email (IAM username) of the user to delete: ").strip()
    delete_user(email)

if __name__ == "__main__":
    main()
