import os
import subrosa

def main():
    # Define your 32-byte message
    message = b'This is a secret 32-bytes message!'

    # Define parameters for Shamir Secret Sharing
    n = 5  # Total number of shares
    k = 3  # Minimum number of shares required to reconstruct the secret

    # Split the secret message into shares
    shares = subrosa.split_secret(message, k, n)

    # Print the generated shares
    print("Shares:")
    for i, share in enumerate(shares):
        print(f"Share {i + 1}: {share}")

    # Simulate selecting k random shares to recover the secret
    selected = ['<subrosa.Share object at 0x1059b3f70>', '<subrosa.Share object at 0x1059b2050>','<subrosa.Share object at 0x1059b2200>']
    selected_shares = [selected[0], selected[1], selected[2]]
    print(selected)
    print(selected_shares)
    # Recover the secret message using the selected shares
    recovered_message = subrosa.recover_secret(selected_shares)
    recovered_message = recovered_message.decode()

    # Print the recovered message
    print("\nRecovered message:")
    print(recovered_message)

if __name__ == "__main__":
    main()
