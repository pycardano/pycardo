import requests
import json

def create_cardano_wallet(name, mnemonic):
    # Specify the Cardano Wallet API endpoint
    api_url = 'https://cardano-wallet-api-url/v2/wallets'

    # Prepare the payload for creating a new wallet
    payload = {
        "name": name,
        "mnemonic_sentence": mnemonic,
        "passphrase": ""
    }

    try:
        # Send a POST request to create the wallet
        response = requests.post(api_url, json=payload)
        
        # Check the response status code
        if response.status_code == 201:
            wallet_data = response.json()
            wallet_id = wallet_data['id']
            print(f"Wallet created successfully! Wallet ID: {wallet_id}")
        else:
            print("Failed to create the wallet.")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


# Example usage:
wallet_name = "MyCardanoWallet"
mnemonic_phrase = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"

create_cardano_wallet(wallet_name, mnemonic_phrase)
