import discord
from discord.ext import commands
from web3 import Web3
import os
from eth_account import Account
from solcx import compile_source
from groq import Groq # type: ignore
from eth_account.hdaccount import generate_mnemonic
from dotenv import load_dotenv
import requests
import hashlib
import json

# Load environment variables
load_dotenv()
LINEARARRAY_AI_KEY = os.getenv("LINEARARRAY_AI_KEY")
INFURA_URL = os.getenv("INFURA_URL")  # Sepolia Ethereum node URL
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# Validate environment variables
if not all([LINEARARRAY_AI_KEY, INFURA_URL, BOT_TOKEN]):
    missing_vars = [var for var, val in {
        "LINEARARRAY_AI_KEY": LINEARARRAY_AI_KEY,
        "INFURA_URL": INFURA_URL,
        "DISCORD_BOT_TOKEN": BOT_TOKEN
    }.items() if not val]
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Web3 setup
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Discord bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# AI Interaction
client = Groq(api_key=LINEARARRAY_AI_KEY)

# Store wallet information (in memory - consider using a database in production)
user_wallets = {}

# Enable HD wallet features
Account.enable_unaudited_hdwallet_features()

# Load wallet data from a JSON file
def load_wallet_data():
    try:
        with open('wallets.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save wallet data to a JSON file
def save_wallet_data():
    with open('wallets.json', 'w') as f:
        json.dump(user_wallets, f)

# Load existing wallet data at startup
user_wallets = load_wallet_data()

def get_lineararray_response(prompt):
    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=1,
        max_tokens=1024,
        top_p=1,
        stream=False,  # Changed to False for simpler handling
        stop=None
    )
    return completion.choices[0].message.content

@bot.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == bot.user:
        return

    # Check if the bot is mentioned
    if bot.user in message.mentions:
        # Remove the mention from the message
        content = message.content.replace(f'<@{bot.user.id}>', '').strip()
        if content:
            response = get_lineararray_response(content)
            await message.reply(response)
    
    # Process commands
    await bot.process_commands(message)

# Updated wallet creation with proper mnemonic generation
@bot.command()
async def create(ctx):
    try:
        user_id = str(ctx.author.id)
        
        # Check if the user already has a wallet
        if user_id in user_wallets:
            existing_wallet = user_wallets[user_id]
            await ctx.send(f"🔐 You already have a wallet!\nAddress: `{existing_wallet['address']}`")
            return
        
        # Generate mnemonic with 12 words in English
        mnemonic_phrase = generate_mnemonic(num_words=12, lang="english")
        
        # Create account from mnemonic
        account = Account.from_mnemonic(mnemonic_phrase)
        
        # Hash the mnemonic for storage
        mnemonic_hash = hashlib.sha256(mnemonic_phrase.encode()).hexdigest()
        
        # Store wallet info
        user_wallets[user_id] = {
            'address': account.address,
            'mnemonic_hash': mnemonic_hash
        }
        
        # Save updated wallet data
        save_wallet_data()
        
        # Send wallet details via DM
        dm_channel = await ctx.author.create_dm()
        await dm_channel.send(
            f"🔐 Your New Wallet:\n\n"
            f"**Address**: `{account.address}`\n\n"
            f"**Mnemonic Phrase** (Keep this secret & safe!):\n"
            f"```{mnemonic_phrase}```\n\n"
            f"⚠️ **IMPORTANT**: Never share your mnemonic phrase with anyone!"
        )
        
        # Send public confirmation in the channel
        embed = discord.Embed(
            title="✅ Wallet Created Successfully",
            description=f"Wallet address: `{account.address}`\n\nCheck your DMs for the secret recovery phrase!",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
        
    except Exception as e:
        error_embed = discord.Embed(
            title="❌ Error Creating Wallet",
            description=str(e),
            color=discord.Color.red()
        )
        await ctx.send(embed=error_embed)

# Add createwall command as an alias for create_wallet
@bot.command()
async def createwall(ctx):
    await create(ctx)

# Add MetaMask connection command
@bot.command()
async def connect_metamask(ctx):
    embed = discord.Embed(
        title="🦊 Connect MetaMask",
        description=(
            "To connect your MetaMask wallet:\n\n"
            "1. Make sure MetaMask is installed in your browser\n"
            "2. Copy your MetaMask wallet address\n"
            "3. Use the command: `!verify_wallet <your_address>`"
        ),
        color=discord.Color.blue()
    )
    await ctx.send(embed=embed)

# Verify wallet ownership
@bot.command()
async def verify_wallet(ctx, address: str):
    try:
        # Generate a random message for signing
        message = f"Verify Discord account {ctx.author.id} at {ctx.message.created_at.timestamp()}"
        
        embed = discord.Embed(
            title="🔐 Verify Wallet Ownership",
            description=(
                f"To verify you own this wallet, please sign this message in MetaMask:\n\n"
                f"```{message}```\n\n"
                f"Then use the command:\n"
                f"`!submit_signature <your_signature>`"
            ),
            color=discord.Color.blue()
        )
        
        # Store the message and address for verification
        user_wallets[str(ctx.author.id)] = {
            'pending_address': address,
            'verify_message': message
        }
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Error initiating verification: {str(e)}")

@bot.command()
async def submit_signature(ctx, signature: str):
    try:
        user_data = user_wallets.get(str(ctx.author.id))
        if not user_data or 'pending_address' not in user_data:
            await ctx.send("❌ Please start the verification process with `!connect_metamask` first!")
            return
            
        # Verify the signature
        message = user_data['verify_message']
        address = user_data['pending_address']
        
        # Recover the address from the signature
        recovered_address = w3.eth.account.recover_message(
            text=message,
            signature=signature
        )
        
        if recovered_address.lower() == address.lower():
            user_wallets[str(ctx.author.id)]['address'] = address
            user_wallets[str(ctx.author.id)]['verified'] = True
            await ctx.send(f"✅ Successfully verified wallet: {address[:6]}...{address[-4:]}")
        else:
            await ctx.send("❌ Signature verification failed!")
            
    except Exception as e:
        await ctx.send(f"❌ Error verifying signature: {str(e)}")

# Check Balance
@bot.command()
async def balance(ctx, user: discord.User = None):
    try:
        # Use the mentioned user's ID if provided, otherwise use the command author's ID
        user_id = str(user.id) if user else str(ctx.author.id)
        
        # Check if the user has a linked wallet
        if user_id in user_wallets and 'address' in user_wallets[user_id]:
            address = user_wallets[user_id]['address']
            eth_balance = w3.eth.get_balance(address)
            eth_balance = w3.from_wei(eth_balance, "ether")
            await ctx.send(f"{user.mention if user else ctx.author.mention}, your balance is: {eth_balance} Sepolia ETH")
        else:
            await ctx.send(f"{user.mention if user else ctx.author.mention}, you don't have a linked wallet. Use `!create` to create one.")
    except Exception as e:
        await ctx.send(f"Error fetching balance: {str(e)}")

# Deploy Smart Contract
@bot.command()
async def deploy(ctx, *, contract_code):
    try:
        compiled_sol = compile_source(contract_code)
        contract_id, contract_interface = compiled_sol.popitem()
        bytecode = contract_interface["bin"]
        abi = contract_interface["abi"]

        account = Account.from_key(os.getenv("PRIVATE_KEY"))
        w3.eth.default_account = account.address

        Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx = Contract.constructor().build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 2000000,
            "gasPrice": w3.to_wei("10", "gwei"),
        })

        signed_tx = w3.eth.account.sign_transaction(tx, account.privateKey)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        await ctx.send(f"Contract Deployed!\nAddress: {receipt.contractAddress}\nTransaction Hash: {tx_hash.hex()}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

# Send Transaction
@bot.command()
async def send_eth(ctx, recipient: str, amount: float):
    try:
        account = Account.from_key(os.getenv("PRIVATE_KEY"))
        txn = {
            "to": recipient,
            "value": w3.to_wei(amount, "ether"),
            "gas": 21000,
            "gasPrice": w3.to_wei("10", "gwei"),
            "nonce": w3.eth.get_transaction_count(account.address),
        }

        signed_tx = w3.eth.account.sign_transaction(txn, account.privateKey)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        await ctx.send(f"Transaction Sent! Hash: {tx_hash.hex()}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

# Update Commands List with cleaned up commands
@bot.command()
async def cmds(ctx):
    commands_info = (
        "**Available Commands:**\n"
        "**Wallet Management:**\n"
        "`!create` - Create a new wallet (details sent via DM).\n"
        "`!connect_metamask` - Link your MetaMask wallet to the bot.\n"
        "`!verify_wallet <address>` - Verify ownership of your wallet.\n"
        "`!balance <wallet_address>` - Check the balance of a given Ethereum address.\n\n"
        "**Transactions & Contracts:**\n"
        "`!send_eth <recipient_address> <amount>` - Send Ethereum to a specified address.\n"
        "`!deploy <contract_code>` - Compile and deploy a smart contract.\n"
        "`!history <address>` - View transaction history.\n\n"
        "**Market Information:**\n"
        "`!price <crypto>` - Get the latest price of a cryptocurrency.\n\n"
        "**Help & Information:**\n"
        "`!workflow` - Shows the workflow of the bot.\n"
        "`!cmds` - Displays this list of available commands.\n\n"
        "**AI Chat:**\n"
        "Simply mention the bot (@BotName) followed by your message to chat with the AI."
    )
    
    embed = discord.Embed(
        title="📋 Command List",
        description=commands_info,
        color=discord.Color.blue()
    )
    await ctx.send(embed=embed)

# Update Workflow command
@bot.command()
async def workflow(ctx):
    workflow_steps = (
        "1. **Create a Wallet**: Use `!create` to generate a non-custodial wallet. The mnemonic phrase is sent via DM.\n"
        "2. **Connect MetaMask**: Use `!connect_metamask` to link your existing MetaMask wallet.\n"
        "3. **Check Balance**: Use `!balance <wallet_address>` to check Sepolia ETH balance.\n"
        "4. **Deploy Smart Contract**: Use `!deploy <contract_code>` to compile and deploy your contract.\n"
        "5. **Send ETH**: Use `!send_eth <recipient_address> <amount>` to send Ethereum transactions.\n"
        "6. **Chat with AI**: Simply mention the bot (@BotName) followed by your message.\n"
        "7. **Security**: Sensitive data is only visible to the user who owns it."
    )
    
    embed = discord.Embed(
        title="🔄 Bot Workflow",
        description=workflow_steps,
        color=discord.Color.green()
    )
    await ctx.send(embed=embed)

# Connect Wallet
@bot.command()
async def connect(ctx):
    try:
        # For demonstration, we'll just create a new wallet
        mnemonic_phrase = generate_mnemonic()
        account = Account.from_mnemonic(mnemonic_phrase)
        dm_channel = await ctx.author.create_dm()
        await dm_channel.send(f"Wallet connected!\nAddress: {account.address}")
        await ctx.send("Wallet connected! Check your DMs for details.")
    except Exception as e:
        await ctx.send(f"Error connecting wallet: {str(e)}")

# Transaction History
@bot.command()
async def history(ctx, user: discord.User = None):
    try:
        # Use the mentioned user's ID if provided, otherwise use the command author's ID
        user_id = str(user.id) if user else str(ctx.author.id)
        
        # Check if the user has a linked wallet
        if user_id in user_wallets and 'address' in user_wallets[user_id]:
            address = user_wallets[user_id]['address']
            
            # Get the latest block number
            latest_block = w3.eth.block_number
            # We'll look at the last 10 blocks for transactions
            transactions = []
            for i in range(max(0, latest_block - 10), latest_block + 1):
                block = w3.eth.get_block(i, full_transactions=True)
                for tx in block.transactions:
                    if tx['from'].lower() == address.lower() or tx['to'] and tx['to'].lower() == address.lower():
                        transactions.append(tx)

            if not transactions:
                await ctx.send(f"{user.mention if user else ctx.author.mention}, no recent transactions found for your address.")
                return

            # Format and send transaction history
            history_text = f"**Recent Transactions for {user.mention if user else ctx.author.mention}:**\n"
            for tx in transactions[:5]:  # Show last 5 transactions
                value_eth = w3.from_wei(tx['value'], 'ether')
                history_text += f"Hash: {tx['hash'].hex()}\n"
                history_text += f"From: {tx['from']}\n"
                history_text += f"To: {tx['to']}\n"
                history_text += f"Value: {value_eth} ETH\n\n"
            
            await ctx.send(history_text)
        else:
            await ctx.send(f"{user.mention if user else ctx.author.mention}, you don't have a linked wallet. Use `!create` to create one.")
    except Exception as e:
        await ctx.send(f"Error fetching history: {str(e)}")

# Crypto Price Check
@bot.command()
async def price(ctx, crypto: str):
    try:
        # Using a simple API to get crypto prices
        crypto = crypto.upper()
        response = await bot.loop.run_in_executor(
            None,
            lambda: requests.get(f"https://api.coingecko.com/api/v3/simple/price?ids={crypto.lower()}&vs_currencies=usd")
        )
        data = response.json()
        
        if crypto.lower() in data:
            price = data[crypto.lower()]['usd']
            await ctx.send(f"{crypto} price: ${price:,.2f} USD")
        else:
            await ctx.send(f"Could not find price for {crypto}")
    except Exception as e:
        await ctx.send(f"Error fetching price: {str(e)}")

bot.run(BOT_TOKEN)

