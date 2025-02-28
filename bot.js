require('dotenv').config();
const crypto = require('crypto'); // For Binance request signing and encryption
const fs = require('fs');
const path = require('path');
const axios = require('axios'); // Ensure axios is required at the top

// Ensure ENCRYPTION_KEY is provided and valid (32-byte hex string)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  console.error('ENCRYPTION_KEY environment variable is not set.');
  process.exit(1);
}
if (Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error('ENCRYPTION_KEY must be a 32-byte key in hex format.');
  process.exit(1);
}

const ALGORITHM = 'aes-256-cbc';

// Encryption helper functions
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  // Return iv and encrypted text, separated by colon.
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  const textParts = encryptedText.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encrypted = textParts.join(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Define file path for local private key storage
const PRIVATE_KEYS_FILE = path.join(__dirname, 'privateKeys.json');

// Helper functions for local private key storage with encryption
function loadLocalPrivateKeys() {
  if (!fs.existsSync(PRIVATE_KEYS_FILE)) {
    return {};
  }
  const data = fs.readFileSync(PRIVATE_KEYS_FILE);
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing local private keys file:', error);
    return {};
  }
}

function saveLocalPrivateKeys(keys) {
  fs.writeFileSync(PRIVATE_KEYS_FILE, JSON.stringify(keys, null, 2));
}

function setLocalPrivateKey(walletId, privateKey) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = encrypt(privateKey);
  keys[walletId] = encryptedKey;
  saveLocalPrivateKeys(keys);
}

function getLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = keys[walletId];
  if (!encryptedKey) return null;
  return decrypt(encryptedKey);
}

function removeLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  delete keys[walletId];
  saveLocalPrivateKeys(keys);
}

// ---------- Binance API Setup ----------

const binanceApiKey = process.env.BINANCE_API_KEY;
const binanceApiSecret = process.env.BINANCE_API_SECRET;
const binanceBaseURL = 'https://api.binance.com';

// Ensure BINANCE_API_SECRET is provided
function signQuery(queryString) {
  if (!binanceApiSecret) {
    throw new Error('BINANCE_API_SECRET is not set in the environment variables.');
  }
  return crypto.createHmac('sha256', binanceApiSecret).update(queryString).digest('hex');
}

async function placeMarketOrder(netAmountUSDT) {
  try {
    const params = new URLSearchParams({
      symbol: 'SOLUSDT',
      side: 'BUY',
      type: 'MARKET',
      quoteOrderQty: netAmountUSDT.toString(),
      timestamp: Date.now().toString()
    });
    const queryString = params.toString();
    const signature = signQuery(queryString);
    params.append('signature', signature);
    const url = `${binanceBaseURL}/api/v3/order?${params.toString()}`;
    const response = await axios.post(url, null, {
      headers: {
        'X-MBX-APIKEY': binanceApiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    return response;
  } catch (error) {
    console.error('❌ Place Market Order Error:', error.response ? error.response.data : error);
    throw error;
  }
}

async function withdrawSOLFromBinance(address, amountSOL) {
  try {
    const params = new URLSearchParams({
      coin: 'SOL',
      address: address,
      amount: amountSOL.toString(),
      network: 'SOL',
      timestamp: Date.now().toString()
    });
    const queryString = params.toString();
    const signature = signQuery(queryString);
    params.append('signature', signature);
    const url = `${binanceBaseURL}/sapi/v1/capital/withdraw/apply?${params.toString()}`;
    const response = await axios.post(url, null, {
      headers: {
        'X-MBX-APIKEY': binanceApiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    return response;
  } catch (error) {
    console.error('❌ Withdraw SOL Error:', error.response ? error.response.data : error);
    throw error;
  }
}

async function realTimeBuyAndWithdrawSOL(ctx, netAmount, userSolAddress) {
  try {
    // 1. Place a market order on Binance to buy SOL using USDT.
    const orderResponse = await placeMarketOrder(netAmount);
    console.log('Market Order Response:', orderResponse.data);
    // "executedQty" typically indicates the amount of SOL acquired.
    const acquiredSol = parseFloat(orderResponse.data.executedQty);
    if (!acquiredSol || acquiredSol <= 0) {
      throw new Error('No SOL acquired from Binance order.');
    }
    console.log(`Acquired SOL: ${acquiredSol}`);
    
    // 2. Withdraw acquired SOL to the user’s wallet address.
    const withdrawResponse = await withdrawSOLFromBinance(userSolAddress, acquiredSol);
    console.log('Withdrawal Response:', withdrawResponse.data);
    
    return {
      acquiredSol: acquiredSol,
      withdrawalId: withdrawResponse.data.id || withdrawResponse.data.withdrawOrderId || JSON.stringify(withdrawResponse.data)
    };
  } catch (error) {
    console.error('❌ RealTimeBuyAndWithdrawSOL Error:', error);
    throw error;
  }
}

async function getBinanceUSDTBalance() {
  try {
    const params = new URLSearchParams({
      timestamp: Date.now().toString()
    });
    const queryString = params.toString();
    const signature = signQuery(queryString);
    params.append('signature', signature);
    const url = `${binanceBaseURL}/api/v3/account?${params.toString()}`;
    const response = await axios.get(url, {
      headers: {
        'X-MBX-APIKEY': binanceApiKey
      }
    });
    // Find asset "USDT" in balances
    const usdtAsset = response.data.balances.find(asset => asset.asset === 'USDT');
    return parseFloat(usdtAsset.free);
  } catch (error) {
    console.error('❌ Error fetching Binance USDT balance:', error.response ? error.response.data : error);
    throw error;
  }
}

// ---------- Import Libraries ----------
const { Telegraf, Markup, session } = require('telegraf');
const { Connection, PublicKey, Keypair, Transaction, SystemProgram } = require('@solana/web3.js');
const admin = require('firebase-admin');
const bs58 = require('bs58');

// ---------- Firebase Initialization ----------
const serviceAccount = require("./solana-farasbots-firebase-adminsdk-fbsvc-da2bd53bc4.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});
const db = admin.firestore();

// ---------- Solana Connection ----------
const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');

// Global subscriptions (prevent duplicate subscriptions)
const subscriptions = {};

// Telegram Bot initialization with session middleware
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
bot.use(session());
bot.use((ctx, next) => {
  ctx.session = ctx.session || {};
  return next();
});

// ---------- Helper Functions ----------

// Decode a Base58 string (Phantom-style)
const decodeBase58 = (str) => {
  if (typeof bs58.decode === 'function') return bs58.decode(str);
  if (bs58.default && typeof bs58.default.decode === 'function') return bs58.default.decode(str);
  throw new Error('Base58 decode function not available.');
};

// Get current SOL price from CoinGecko
const getSolPrice = async () => {
  try {
    const res = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    return res.data.solana.usd;
  } catch (error) {
    console.error('❌ SOL Price Error:', error);
    return null;
  }
};

// Validate if an address is a valid Solana public key
const isValidSolanaAddress = (address) => {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
};

// Calculate net amount after fee (default fee 2% for send, 3% for cash buy)
const calculateNetAmount = (amount, feeRate = 0.02) => {
  const fee = amount * feeRate;
  const netAmount = amount - fee;
  return { fee, netAmount };
};

// Save transaction details to Firebase
const saveTransaction = async (userId, type, amountSOL, amountUSD, address, txId) => {
  try {
    await db.collection('transactions').add({
      userId: userId.toString(),
      type,
      amountSOL,
      amountUSD,
      address,
      transactionId: txId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log('💾 Transaction saved.');
  } catch (error) {
    console.error('❌ Transaction Save Error:', error);
  }
};

// Listen for incoming transactions for real-time updates
const listenForIncomingTransactions = async (publicKey) => {
  if (subscriptions[publicKey]) {
    console.log(`🔔 Already subscribed for ${publicKey}`);
    return;
  }
  try {
    const subId = connection.onAccountChange(
      new PublicKey(publicKey),
      (accountInfo) => {
        console.log(`🔔 Update for ${publicKey}:`, accountInfo);
      },
      'confirmed'
    );
    subscriptions[publicKey] = subId;
    console.log(`👂 Listening on ${publicKey} (sub ID: ${subId})`);
  } catch (error) {
    console.error('❌ Subscription Error:', error);
  }
};

// ---------- Wallet Management Functions ----------

/**
 * Create a new wallet.
 * Note: Private key is NOT stored in Firebase. Instead, it is stored locally in encrypted form.
 */
const createNewWallet = async (userId, phone, firstName, lastName, username, email) => {
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toString();
  const privateKeyHex = Buffer.from(keypair.secretKey).toString('hex');

  const userRef = db.collection('users').doc(userId.toString());
  await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });

  const walletData = {
    publicKey,
    type: 'new',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  const walletRef = await userRef.collection('wallets').add(walletData);
  await userRef.update({ activeWalletId: walletRef.id });
  await listenForIncomingTransactions(publicKey);

  // Store encrypted private key locally
  setLocalPrivateKey(walletRef.id, privateKeyHex);

  return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
};

/**
 * Import wallet using a provided private key (Base58 format).
 * Private key is stored locally in encrypted form.
 */
const importWalletByPrivateKey = async (userId, phone, firstName, lastName, username, email, privateKeyBs58) => {
  try {
    const secretKeyUint8 = decodeBase58(privateKeyBs58);
    let keypair;
    try {
      keypair = Keypair.fromSecretKey(secretKeyUint8);
    } catch {
      try {
        keypair = Keypair.fromSeed(secretKeyUint8);
      } catch {
        throw new Error('❌ Invalid private key format.');
      }
    }
    const publicKey = keypair.publicKey.toString();
    const userRef = db.collection('users').doc(userId.toString());
    await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });

    const walletData = {
      publicKey,
      type: 'import',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    const walletRef = await userRef.collection('wallets').add(walletData);
    await userRef.update({ activeWalletId: walletRef.id });
    await listenForIncomingTransactions(publicKey);

    // Store encrypted private key locally
    setLocalPrivateKey(walletRef.id, privateKeyBs58);

    return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
  } catch (error) {
    console.error('❌ Wallet Import Error:', error);
    throw error;
  }
};

/**
 * Recover wallet by phrase (for demo, creates a new wallet).
 * Private key storage follows the same logic as createNewWallet.
 */
const recoverWalletByPhrase = async (userId, phone, firstName, lastName, username, email, phrase) => {
  try {
    return await createNewWallet(userId, phone, firstName, lastName, username, email);
  } catch (error) {
    console.error('❌ Wallet Recovery Error:', error);
    throw error;
  }
};

/**
 * Get the active wallet for a user.
 * Note: This returns the wallet data stored in Firebase (which does not include the private key).
 */
const getActiveWallet = async (userId) => {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists || !userDoc.data().activeWalletId) return null;
  const walletRef = userRef.collection('wallets').doc(userDoc.data().activeWalletId);
  const walletDoc = await walletRef.get();
  return walletDoc.exists ? { id: walletDoc.id, ...walletDoc.data() } : null;
};

const listWallets = async (userId) => {
  const snapshot = await db.collection('users').doc(userId.toString()).collection('wallets').get();
  const wallets = [];
  snapshot.forEach(doc => wallets.push({ id: doc.id, ...doc.data() }));
  return wallets;
};

// ---------- Wallet Reset Function ----------

/**
 * Resets the user's active wallet by:
 *  1) Generating a new wallet.
 *  2) Setting it as activeWalletId.
 *  3) Marking old wallet as "discarded" and removing its local private key.
 */
const resetWallet = async (userId) => {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists) throw new Error('User not found');

  const userData = userDoc.data();
  const phone = userData.phone || 'Not provided';
  const firstName = userData.firstName || 'Not provided';
  const lastName = userData.lastName || 'Not provided';
  const username = userData.username || 'Not provided';
  const email = userData.email || 'Not provided';

  const newWallet = await createNewWallet(userId, phone, firstName, lastName, username, email);

  if (userData.activeWalletId) {
    const oldWalletRef = userRef.collection('wallets').doc(userData.activeWalletId);
    await oldWalletRef.update({ discarded: true, discardedAt: admin.firestore.FieldValue.serverTimestamp() });
    removeLocalPrivateKey(userData.activeWalletId);
  }

  return newWallet;
};

// ---------- Telegram Bot Commands & Actions ----------

bot.command('start', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const firstName = ctx.from.first_name || 'User';
    const currentHour = new Date().getHours();
    const greeting = currentHour < 12
      ? '🌞 Good Morning'
      : currentHour < 18
      ? `🌤️ Good Afternoon, ${firstName}!`
      : '🌙 Good Evening';

    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      await ctx.reply(
        `${greeting}\n\nWelcome to *FarasBot on Solana* 🚀\n` +
        `Manage your wallet with speed and security.\n\n` +
        `Choose one of the options below to get started:\n` +
        `• *🆕 New Account* – Create a new wallet.\n` +
        `• *🔑 Import Private Key* – Import your existing wallet.\n` +
        `• *🔄 Recover Phrase* – Recover your wallet using your recovery phrase.\n`,
        {
          parse_mode: 'Markdown',
          ...Markup.inlineKeyboard([
            [Markup.button.callback('🆕 New Account', 'new_account'),
             Markup.button.callback('🔑 Import Private Key', 'import_key')],
            [Markup.button.callback('🔄 Recover Phrase', 'recover_phrase')]
          ])
        }
      );
      return;
    } else {
      const activeWallet = await getActiveWallet(userId);
      if (!activeWallet) {
        await ctx.reply('❌ No active wallet found. Please add a wallet via Settings.');
        return;
      }
      const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
      const balanceSOL = balance / 1e9;
      const solPrice = await getSolPrice();
      const balanceUSD = (balanceSOL * solPrice).toFixed(2);

      await ctx.reply(
        `🚀 *Welcome Back! ${greeting}*\n\n` +
        `👋 *Active Wallet:* I'm here to help you manage your Solana wallet.\n\n` +
        `*Faras on Solana* – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\n` +
        `🌐 *Wallet SOLANA*\n\n` +
        `Let's get started! How would you like to trade today?\n\n` +
        `*Wallet Address:* \`${activeWallet.publicKey}\`\n\n` +
        `*Balance:* ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\n` +
        `*What would you like to do?* `,
        {
          parse_mode: 'Markdown',
          ...Markup.inlineKeyboard([
            [Markup.button.callback('💰 Cash Buy', 'cash_buy'),
             Markup.button.callback('💸 Send SOL', 'send'),
             Markup.button.callback('📥 Receive SOL', 'receive')],
            [Markup.button.callback('🔄 Refresh Balance', 'refresh')],
            [Markup.button.callback('❓ Help', 'help'),
             Markup.button.callback('⚙️ Settings', 'settings')]
          ])
        }
      );
    }
  } catch (error) {
    console.error('❌ /start Error:', error);
    await ctx.reply('❌ Oops! An error occurred. Please try again later.');
  }
});

// New Account, Import, and Recover Actions
bot.action('new_account', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const phone = ctx.from.phone_number || 'Not provided';
    const firstName = ctx.from.first_name || 'Not provided';
    const lastName = ctx.from.last_name || 'Not provided';
    const username = ctx.from.username || 'Not provided';
    const email = ctx.from.email || 'Not provided';

    const wallet = await createNewWallet(userId, phone, firstName, lastName, username, email);
    ctx.session.secretKey = Array.from(wallet.secretKey);
    await ctx.reply(
      `✅ *Wallet Created Successfully!*\n\n` +
      `*Address:* ${wallet.publicKey}\n\n` +
      `Your private key is stored locally in encrypted form. To view it, use *Settings → Private Key*.`,
      { parse_mode: 'Markdown' }
    );
    ctx.answerCbQuery();
    ctx.telegram.sendMessage(ctx.chat.id, '👉 Type /start to continue.');
  } catch (error) {
    console.error('❌ New Account Error:', error);
    await ctx.reply('❌ Error while creating a new wallet.');
  }
});

bot.action('import_key', async (ctx) => {
  try {
    ctx.session.awaitingPrivateKey = true;
    await ctx.reply(
      '🔑 *Import Wallet*\n\nPlease enter your private key in Base58 format (Phantom-style, approx. 88 characters):',
      { parse_mode: 'Markdown' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Import Key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('recover_phrase', async (ctx) => {
  try {
    ctx.session.awaitingRecoveryPhrase = true;
    await ctx.reply(
      '🔄 *Recover Wallet*\n\nEnter your recovery phrase (words separated by a space):',
      { parse_mode: 'Markdown' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Recover Phrase Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Text listener for Import / Recovery and transaction flows
bot.on('text', async (ctx) => {
  try {
    if (ctx.session.awaitingPrivateKey) {
      const text = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await importWalletByPrivateKey(userId, phone, firstName, lastName, username, email, text);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ *Wallet Imported!*\n\n*Address:* ${wallet.publicKey}\n\nTo view your private key later, use *Settings → Private Key*.`,
          { parse_mode: 'Markdown' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to import wallet. Please check your private key and try again.');
      }
      ctx.session.awaitingPrivateKey = false;
      return;
    }

    if (ctx.session.awaitingRecoveryPhrase) {
      const phrase = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await recoverWalletByPhrase(userId, phone, firstName, lastName, username, email, phrase);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ *Wallet Recovered!*\n\n*Address:* ${wallet.publicKey}\n\nTo view your private key later, use *Settings → Private Key*.`,
          { parse_mode: 'Markdown' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to recover wallet. Please check your recovery phrase and try again.');
      }
      ctx.session.awaitingRecoveryPhrase = false;
      return;
    }

    // -------------- SEND FLOW --------------
    if (ctx.session.sendFlow) {
      if (ctx.session.sendFlow.action === 'awaiting_address') {
        const toAddress = ctx.message.text.trim();
        if (!isValidSolanaAddress(toAddress)) {
          await ctx.reply('❌ Invalid SOL address. Please try again.');
          return;
        }
        ctx.session.sendFlow.action = 'awaiting_amount';
        ctx.session.sendFlow.toAddress = toAddress;
        await ctx.reply('💰 Enter the USD amount you want to send (minimum $1):');
        return;
      } else if (ctx.session.sendFlow.action === 'awaiting_amount') {
        const amountUSD = parseFloat(ctx.message.text);
        if (isNaN(amountUSD) || amountUSD < 0.5) {
          await ctx.reply('❌ Please enter a valid amount (minimum $1).');
          return;
        }
        const solPrice = await getSolPrice();
        if (!solPrice) {
          await ctx.reply('❌ Unable to fetch SOL price. Try again later.');
          return;
        }
        const amountSOL = amountUSD / solPrice;
        ctx.session.sendFlow.amountSOL = amountSOL;
        ctx.session.sendFlow.amountUSD = amountUSD;
        await ctx.reply(
          `⚠️ Confirm:\nSend *${amountSOL.toFixed(4)} SOL* (≈ $${amountUSD.toFixed(2)}) to:\n${ctx.session.sendFlow.toAddress}`,
          {
            parse_mode: 'Markdown',
            ...Markup.inlineKeyboard([
              [Markup.button.callback('✅ Confirm', 'confirm_send'),
               Markup.button.callback('❌ Cancel', 'cancel_send')]
            ])
          }
        );
        return;
      }
    }

    // -------------- CASH BUY FLOW --------------
    if (ctx.session.cashBuy) {
      const cashBuy = ctx.session.cashBuy;
      if (cashBuy.step === 'phoneNumber') {
        const phoneNumber = ctx.message.text.trim();
        if (!/^\d{9}$/.test(phoneNumber)) {
          await ctx.reply('❌ Invalid phone number. Please enter a 9-digit number.');
          return;
        }
        cashBuy.phoneNumber = phoneNumber;
        cashBuy.step = 'amount';
        await ctx.reply('💵 Enter the USD amount you wish to purchase:');
        return;
      } else if (cashBuy.step === 'amount') {
        const amount = parseFloat(ctx.message.text);
        if (isNaN(amount) || amount <= 0) {
          await ctx.reply('❌ Invalid amount. Please enter a valid number.');
          return;
        }
        cashBuy.amount = amount;
        cashBuy.step = 'confirm';
        const fee = amount * 0.03;
        const netAmount = amount - fee;
        const solPrice = await getSolPrice();
        const solReceived = netAmount / solPrice;
        await ctx.reply(
          `💵 Amount: $${amount}\n💸 Fee (3%): $${fee.toFixed(2)}\n💰 Net: $${netAmount.toFixed(2)}\n🪙 ≈ ${solReceived.toFixed(4)} SOL\n\nProceed?`,
          {
            reply_markup: {
              inline_keyboard: [
                [{ text: '✅ Submit', callback_data: 'submit' },
                 { text: '❌ Cancel', callback_data: 'cancel' }]
              ]
            }
          }
        );
        return;
      }
    }
  } catch (error) {
    console.error('❌ Text Handler Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Refresh Balance
bot.action('refresh', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    await ctx.reply(`🔄 Balance: *${balanceSOL.toFixed(4)} SOL* (~$${balanceUSD} USD)`, { parse_mode: 'Markdown' });
  } catch (error) {
    console.error('❌ Refresh Balance Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Send Flow
bot.action('send', async (ctx) => {
  try {
    ctx.session.sendFlow = { action: 'awaiting_address' };
    await ctx.reply('📤 Enter the recipient SOL address:');
  } catch (error) {
    console.error('❌ Send Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('receive', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
    await ctx.reply(`📥 *Your SOL Address:*\n${activeWallet.publicKey}`, { parse_mode: 'Markdown' });
  } catch (error) {
    console.error('❌ Receive Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('confirm_send', async (ctx) => {
  try {
    if (!ctx.session.sendFlow || !ctx.session.sendFlow.toAddress) {
      await ctx.reply('❌ Transaction not initiated properly.');
      return;
    }
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
      ctx.session.sendFlow = null;
      return;
    }
    // Retrieve the locally stored (encrypted) private key using wallet ID from Firebase
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      await ctx.reply('❌ Private key missing. Please import your wallet using /import_key.');
      return;
    }

    let fromKeypair;
    if (activeWallet.type === 'import') {
      fromKeypair = Keypair.fromSecretKey(decodeBase58(storedPrivateKey));
    } else {
      fromKeypair = Keypair.fromSecretKey(Buffer.from(storedPrivateKey, 'hex'));
    }

    const toPublicKey = new PublicKey(ctx.session.sendFlow.toAddress);
    const balance = await connection.getBalance(fromKeypair.publicKey);
    const balanceSOL = balance / 1e9;
    if (balanceSOL < ctx.session.sendFlow.amountSOL) {
      await ctx.reply('❌ Insufficient SOL balance.');
      ctx.session.sendFlow = null;
      return;
    }
    const lamports = Math.round(ctx.session.sendFlow.amountSOL * 1e9);
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: fromKeypair.publicKey,
        toPubkey: toPublicKey,
        lamports,
      })
    );
    const signature = await connection.sendTransaction(transaction, [fromKeypair]);
    await saveTransaction(
      userId,
      'send',
      ctx.session.sendFlow.amountSOL,
      ctx.session.sendFlow.amountUSD,
      ctx.session.sendFlow.toAddress,
      signature
    );
    await ctx.reply(
      `✅ *Transaction Successful!*\n\nYou sent *${ctx.session.sendFlow.amountSOL.toFixed(4)} SOL* (≈ $${ctx.session.sendFlow.amountUSD.toFixed(2)}) to:\n${ctx.session.sendFlow.toAddress}\n\n*TX ID:* ${signature}`,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.url('🔍 View on Solscan', `https://solscan.io/tx/${signature}`)],
          [Markup.button.callback('❌ Close', 'close_message')]
        ]),
      }
    );
    ctx.session.sendFlow = null;
  } catch (error) {
    console.error('❌ Confirm Send Error:', error);
    if (error.message && error.message.includes("insufficient funds for rent")) {
      await ctx.reply('❌ Transaction failed due to insufficient funds for fees.');
    } else {
      await ctx.reply('❌ An error occurred. Please try again later.');
    }
  }
});

bot.action('cancel_send', async (ctx) => {
  try {
    await ctx.reply('❌ Transaction canceled.');
    ctx.session.sendFlow = null;
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Send Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Cash Buy
bot.action('cash_buy', (ctx) => {
  ctx.session.cashBuy = {};
  ctx.reply('💳 *Purchase SOL*\n\nChoose a payment method:', {
    reply_markup: {
      inline_keyboard: [
        [{ text: 'EVC Plus', callback_data: 'evcplus' }, { text: 'Zaad', callback_data: 'zaad' }],
        [{ text: 'Sahal', callback_data: 'sahal' }],
        [{ text: '🔙 Back', callback_data: 'back_to_main' }]
      ]
    },
    parse_mode: 'Markdown'
  });
});

bot.action(['evcplus', 'zaad', 'sahal'], (ctx) => {
  ctx.session.cashBuy.paymentMethod = ctx.match[0];
  ctx.session.cashBuy.step = 'phoneNumber';
  ctx.reply(`You selected *${ctx.match[0].toUpperCase()}*.\n\nPlease enter your 9-digit phone number:`, { parse_mode: 'Markdown' });
});

bot.action('submit', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
      return;
    }
    ctx.session.cashBuy.solAddress = activeWallet.publicKey;
    ctx.session.cashBuy.step = 'processing';
    await ctx.reply(`Using your SOL address:\n*${activeWallet.publicKey}*\n\nProcessing payment... ⏳`, { parse_mode: 'Markdown' });
    await processPayment(ctx, {
      phoneNumber: ctx.session.cashBuy.phoneNumber,
      amount: ctx.session.cashBuy.amount,
      solAddress: activeWallet.publicKey,
      paymentMethod: ctx.session.cashBuy.paymentMethod
    });
  } catch (error) {
    console.error('❌ Cash Buy Submit Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('cancel', (ctx) => {
  ctx.reply('❌ Transaction cancelled. Returning to main menu...', {
    reply_markup: {
      inline_keyboard: [
        [{ text: '💰 Buy SOL', callback_data: 'cash_buy' },
         { text: '💸 Sell SOL', callback_data: 'sell' }]
      ]
    }
  });
  ctx.session.cashBuy = null;
});

// Payment Processor
async function processPayment(ctx, { phoneNumber, amount, solAddress, paymentMethod }) {
  try {
    const paymentBody = {
      schemaVersion: '1.0',
      requestId: Date.now().toString(),
      timestamp: Date.now(),
      channelName: 'WEB',
      serviceName: 'API_PURCHASE',
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        paymentMethod: 'mwallet_account',
        payerInfo: { accountNo: phoneNumber },
        transactionInfo: {
          referenceId: '12334',
          invoiceId: '7896504',
          amount,
          currency: 'USD',
          description: 'SOL Purchase'
        }
      }
    };

    console.log('Payment Request Body:', paymentBody);
    const response = await axios.post('https://api.waafipay.net/asm', paymentBody);
    console.log('Payment Response:', response.data);

    if (response.data?.status === 'FAILED') {
      console.error('❌ Payment failed:', response.data);
      await ctx.reply('❌ Payment failed. Please try again.');
      return;
    }

    console.log('✅ Payment verified successfully.');
    await ctx.reply('⌛ Payment processing... please wait a minute.');

    const fee = amount * 0.03;
    const netAmountForConversion = amount - fee;
    
    const availableUSDT = await getBinanceUSDTBalance();
    if (availableUSDT < netAmountForConversion) {
      await ctx.reply(`❌ Insufficient Binance USDT balance. Available: $${availableUSDT.toFixed(2)} USDT, required: $${netAmountForConversion.toFixed(2)} USDT. Please deposit more funds and try again.`);
      return;
    }
    
    const result = await realTimeBuyAndWithdrawSOL(ctx, netAmountForConversion, solAddress);
    
    await ctx.reply(
      `🎉 *Congratulations!*\nYour purchase is complete.\nNet Amount: $${netAmountForConversion.toFixed(2)} USD was used to buy SOL.\nAcquired SOL: ${result.acquiredSol.toFixed(4)} SOL.\nWithdrawal ID: ${result.withdrawalId}\n\nPlease allow a few minutes for your SOL to arrive in your wallet.\nFor support, contact our help center.`,
      {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '❓ Help / Contact', callback_data: 'help_center' }]
          ]
        }
      }
    );
    ctx.session.cashBuy = null;
  } catch (error) {
    console.error('❌ Payment Processing Error:', error);
    await ctx.reply('❌ Payment error. Please try again later.');
    ctx.session.cashBuy = null;
  }
}

// Settings
bot.action('settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ *Settings Menu*\n\n1. *Private Key* - View your wallet’s private key.\n2. *Manage Wallet* - Switch between wallets.\n3. *Reset Wallet* - Discard old wallet & create a new one.\n\n⚠️ **WARNING:** Never share your private key with anyone!`,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('🔐 Private Key', 'show_private_key')],
          [Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')],
          [Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt')],
          [Markup.button.callback('🔙 Back', 'back_to_main')]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

/**
 * STEP 1: Show disclaimers & wait for user confirmation
 */
bot.action('show_private_key', async (ctx) => {
  try {
    const disclaimerText = 
      `*Keep Your Private Key Secret*\n\n` +
      `• Your Private Key will provide access to this account. Think of it as a login and password combined into one.\n` +
      `• Anyone who has this Private Key will have full access to any funds in this account. Your funds may be lost.\n` +
      `• Do not share your Private Key with any 3rd party, person, website, or application.\n\n` +
      `I will not share my Private Key with any 3rd party, person, website, or application.\n\n` +
      `Press *Continue* to reveal your Private Key.`;

    await ctx.editMessageText(disclaimerText, {
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('❌ Cancel', 'back_to_settings'),
         Markup.button.callback('Continue', 'confirm_show_private_key')]
      ])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

/**
 * STEP 2: Reveal the actual private key using local encrypted storage.
 */
bot.action('confirm_show_private_key', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
    }
    // Retrieve private key from local encrypted storage
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      return ctx.reply('❌ Private key not available. Please import your wallet.');
    }
    const privateKeyMsg = 
      `*Your Private Key*\n\n` +
      `\`${storedPrivateKey}\`\n\n` +
      `If someone has your Private Key, they will have full control of your wallet.\n\n` +
      `⚠️ *SECURITY WARNING:* Never share this key with anyone.\n` +
      `Store it offline in a secure location.`;

    await ctx.editMessageText(privateKeyMsg, {
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('Done', 'back_to_settings')]
      ])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ confirm_show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Manage Wallet
bot.action('manage_wallet', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const wallets = await listWallets(userId);
    if (wallets.length === 0) {
      await ctx.reply('❌ No wallets found. Please create or import a wallet first.');
      return;
    }
    const keyboard = wallets.map(w => [Markup.button.callback(w.publicKey, `select_wallet_${w.id}`)]);
    keyboard.push([Markup.button.callback('🔙 Back', 'back_to_settings')]);
    await ctx.editMessageText('🗄️ *Select Wallet:*\nChoose the wallet you wish to use:', {
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard(keyboard)
    });
  } catch (error) {
    console.error('❌ Manage Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action(/select_wallet_(.+)/, async (ctx) => {
  try {
    const walletId = ctx.match[1];
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    await userRef.update({ activeWalletId: walletId });
    ctx.session.secretKey = null;
    await ctx.reply('✅ Active wallet updated. (If needed, import its private key via /import_key).');
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Select Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('back_to_settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ *Settings Menu*\n\n1. *Private Key*\n2. *Manage Wallet*\n3. *Reset Wallet*\n\n⚠️ **WARNING:** Never share your private key!`,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('🔐 Private Key', 'show_private_key')],
          [Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')],
          [Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt')],
          [Markup.button.callback('🔙 Back', 'back_to_main')]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// ------------------- RESET WALLET FLOW -------------------

bot.action('reset_wallet_prompt', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚠️ *RESET WALLET*\n\nAre you sure you want to reset your BONKbot Wallet?\n\n` +
      `**WARNING!** This action will create a brand-new wallet and discard your old one.\n\n` +
      `Please ensure you have exported your private key / seed phrase to avoid permanent loss of any funds on the old wallet.\n\n` +
      `*This action is irreversible!*`,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ Confirm', 'reset_wallet_confirm')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_prompt Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('reset_wallet_confirm', async (ctx) => {
  try {
    await ctx.editMessageText(
      `CONFIRM: Are you *absolutely sure* you want to reset your BONKbot Wallet?\n\n` +
      `Once done, you **cannot** recover your old wallet from this bot.\n\n` +
      `Last chance to cancel!`,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ FINAL CONFIRM', 'reset_wallet_final')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_confirm Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('reset_wallet_final', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const newWallet = await resetWallet(userId);

    await ctx.editMessageText(
      `✅ *Wallet Reset Successful!*\n\n` +
      `A brand-new wallet has been created and set as active.\n` +
      `*New Address:* \`${newWallet.publicKey}\`\n\n` +
      `Your old wallet has been discarded. Ensure you had its private key if you still need it.\n` +
      `Type /start to refresh or explore the new wallet.`,
      {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '🔙 Back to Main Menu', callback_data: 'back_to_main' }]
          ]
        }
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_final Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// ------------------- END RESET WALLET FLOW -------------------

bot.action('back_to_main', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    ctx.session.sendFlow = null;
    ctx.session.cashBuy = null;
    await ctx.editMessageText(
      `🚀 *Welcome Back!*\n\n` +
      `👋 *Active Wallet:* I'm here to help you manage your Solana wallet.\n\n` +
      `*Faras on Solana* – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\n` +
      `*Wallet Address:* \`${activeWallet.publicKey}\`\n\n` +
      `*Balance:* ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\n` +
      `*What would you like to do?*  `,
      {
        parse_mode: 'Markdown',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('💰 Cash Buy', 'cash_buy'),
           Markup.button.callback('💸 Send SOL', 'send'),
           Markup.button.callback('📥 Receive SOL', 'receive')],
          [Markup.button.callback('🔄 Refresh Balance', 'refresh')],
          [Markup.button.callback('❓ Help', 'help'),
           Markup.button.callback('⚙️ Settings', 'settings')]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Main Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('close_message', async (ctx) => {
  try {
    await ctx.reply('🎉 *Transaction Completed Successfully!*', { parse_mode: 'Markdown' });
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Close Message Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// Launch the bot
bot.launch()
  .then(() => console.log('🚀 Bot is live!'))
  .catch((error) => {
    console.error('❌ Bot Launch Error:', error);
  });
