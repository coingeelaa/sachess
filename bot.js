require('dotenv').config();
const crypto = require('crypto'); // For Binance request signing and encryption
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// --- Encryption & Local Key Storage Setup ---
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

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
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

const PRIVATE_KEYS_FILE = path.join(__dirname, 'privateKeys.json');
function loadLocalPrivateKeys() {
  if (!fs.existsSync(PRIVATE_KEYS_FILE)) return {};
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

// --- Binance API Setup ---
const binanceApiKey = process.env.BINANCE_API_KEY;
const binanceApiSecret = process.env.BINANCE_API_SECRET;
const binanceBaseURL = 'https://api.binance.com';

function signQuery(queryString) {
  if (!binanceApiSecret) {
    throw new Error('BINANCE_API_SECRET is not set in the environment variables.');
  }
  return crypto.createHmac('sha256', binanceApiSecret).update(queryString).digest('hex');
}
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Check available USDT balance in Binance account.
async function getBinanceUSDTBalance() {
  try {
    const params = new URLSearchParams({ timestamp: Date.now().toString() });
    const queryString = params.toString();
    const signature = signQuery(queryString);
    params.append('signature', signature);
    const url = `${binanceBaseURL}/api/v3/account?${params.toString()}`;
    const response = await axios.get(url, { headers: { 'X-MBX-APIKEY': binanceApiKey } });
    const usdtAsset = response.data.balances.find(asset => asset.asset === 'USDT');
    return parseFloat(usdtAsset.free);
  } catch (error) {
    console.error('❌ Error fetching Binance USDT balance:', error.response ? error.response.data : error);
    throw error;
  }
}

// Place Market Order to buy SOL using USDT.
async function placeMarketOrder(netAmountUSDT) {
  const availableUSDT = await getBinanceUSDTBalance();
  if (availableUSDT < netAmountUSDT) {
    throw new Error(`Insufficient USDT balance: available ${availableUSDT}, required ${netAmountUSDT}`);
  }
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

// Withdraw SOL from Binance to external wallet address.
async function withdrawSOLFromBinance(address, amountSOL) {
  try {
    const params = new URLSearchParams({
      coin: 'SOL',
      address: address,
      amount: amountSOL,
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

// --- Real-Time Process for Buying & Withdrawing SOL ---
const MIN_WITHDRAWAL_AMOUNT = 0.10000000;
async function realTimeBuyAndWithdrawSOL(ctx, netAmount, userSolAddress) {
  try {
    // 1. Place market order
    const orderResponse = await placeMarketOrder(netAmount);
    console.log('Market Order Response:', orderResponse.data);
    const acquiredSol = parseFloat(orderResponse.data.executedQty);
    if (!acquiredSol || acquiredSol <= 0) {
      throw new Error('No SOL acquired from Binance order.');
    }
    console.log(`Acquired SOL: ${acquiredSol}`);
    
    // Wait 10 seconds for balance update
    console.log('Waiting 10 seconds for internal balance update...');
    await delay(10000);
    
    // 2. Deduct withdrawal fee and check minimum withdrawal amount
    const withdrawalFee = 0.01;
    if (acquiredSol <= withdrawalFee) {
      throw new Error('Acquired SOL is not sufficient to cover the withdrawal fee.');
    }
    const netSol = acquiredSol - withdrawalFee;
    if (netSol < MIN_WITHDRAWAL_AMOUNT) {
      throw new Error(`Net SOL (${netSol.toFixed(8)}) is less than the minimum withdrawal amount (${MIN_WITHDRAWAL_AMOUNT}).`);
    }
    const netSolString = netSol.toFixed(8);
    console.log(`Withdrawal Fee: ${withdrawalFee} SOL, Net SOL to withdraw: ${netSolString}`);
    
    // 3. Withdraw SOL
    const withdrawResponse = await withdrawSOLFromBinance(userSolAddress, netSolString);
    console.log('Withdrawal Response:', withdrawResponse.data);
    
    return {
      acquiredSol,
      withdrawalFee,
      netSol,
      withdrawalId: withdrawResponse.data.id || withdrawResponse.data.withdrawOrderId || JSON.stringify(withdrawResponse.data)
    };
  } catch (error) {
    console.error('❌ RealTimeBuyAndWithdrawSOL Error:', error);
    throw error;
  }
}

// --- Import Libraries for Telegram Bot, Solana and Firebase ---
const { Telegraf, Markup, session } = require('telegraf');
const { Connection, PublicKey, Keypair, Transaction, SystemProgram } = require('@solana/web3.js');
const admin = require('firebase-admin');
const bs58 = require('bs58');

const serviceAccount = require("./solana-farasbots-firebase-adminsdk-fbsvc-da2bd53bc4.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});
const db = admin.firestore();
const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');
const subscriptions = {};

const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
bot.use(session());
bot.use((ctx, next) => {
  ctx.session = ctx.session || {};
  return next();
});

// --- Helper Functions for Bot ---
const decodeBase58 = (str) => {
  if (typeof bs58.decode === 'function') return bs58.decode(str);
  if (bs58.default && typeof bs58.default.decode === 'function') return bs58.default.decode(str);
  throw new Error('Base58 decode function not available.');
};

const getSolPrice = async () => {
  try {
    const res = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    return res.data.solana.usd;
  } catch (error) {
    console.error('❌ SOL Price Error:', error);
    return null;
  }
};

const isValidSolanaAddress = (address) => {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
};

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

// --- Wallet Management Functions ---
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
  setLocalPrivateKey(walletRef.id, privateKeyHex);
  return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
};

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
    setLocalPrivateKey(walletRef.id, privateKeyBs58);
    return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
  } catch (error) {
    console.error('❌ Wallet Import Error:', error);
    throw error;
  }
};

const recoverWalletByPhrase = async (userId, phone, firstName, lastName, username, email, phrase) => {
  try {
    return await createNewWallet(userId, phone, firstName, lastName, username, email);
  } catch (error) {
    console.error('❌ Wallet Recovery Error:', error);
    throw error;
  }
};

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

// --- Telegram Bot Commands & Actions ---

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
            [{ text: '💰 Cash Buy', callback_data: 'cash_buy' },
             { text: '💸 Send SOL', callback_data: 'send' },
             { text: '📥 Receive SOL', callback_data: 'receive' }],
            [{ text: '🔄 Refresh Balance', callback_data: 'refresh' }],
            [{ text: '❓ Help', callback_data: 'help' },
             { text: '⚙️ Settings', callback_data: 'settings' }]
          ])
        }
      );
    }
  } catch (error) {
    console.error('❌ /start Error:', error);
    await ctx.reply('❌ Oops! An error occurred. Please try again later.');
  }
});

// ===== CASH BUY FLOW (Updated to use new messages for Submit/Cancel) =====

bot.action('cash_buy', async (ctx) => {
  // Start cash buy process and store chat/message info for later use.
  ctx.session.cashBuy = { chatId: ctx.chat.id, messageId: ctx.callbackQuery.message.message_id };
  await ctx.editMessageText('💳 *Purchase SOL*\n\nChoose a payment method:', {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [
        [{ text: 'EVC Plus', callback_data: 'evcplus' }, { text: 'Zaad', callback_data: 'zaad' }],
        [{ text: 'Sahal', callback_data: 'sahal' }],
        [{ text: '🔙 Back', callback_data: 'back_to_main' }]
      ]
    }
  });
});

bot.action(['evcplus', 'zaad', 'sahal'], async (ctx) => {
  ctx.session.cashBuy.paymentMethod = ctx.match[0];
  ctx.session.cashBuy.step = 'phoneNumber';
  await ctx.editMessageText(
    `You selected *${ctx.match[0].toUpperCase()}*.\n\nPlease enter your 9-digit phone number:`,
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: '🔙 Back', callback_data: 'cash_buy_back' }]
        ]
      }
    }
  );
  ctx.answerCbQuery();
});

bot.action('cash_buy_back', async (ctx) => {
  ctx.session.cashBuy = { chatId: ctx.chat.id, messageId: ctx.callbackQuery.message.message_id };
  await ctx.editMessageText('💳 *Purchase SOL*\n\nChoose a payment method:', {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [
        [{ text: 'EVC Plus', callback_data: 'evcplus' }, { text: 'Zaad', callback_data: 'zaad' }],
        [{ text: 'Sahal', callback_data: 'sahal' }],
        [{ text: '🔙 Back', callback_data: 'back_to_main' }]
      ]
    }
  });
  ctx.answerCbQuery();
});

// Process text messages for cashBuy steps
bot.on('text', async (ctx) => {
  try {
    // ----- IMPORT WALLET & RECOVERY FLOW (unchanged) -----
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
          `✅ *Wallet Imported!*\n\n*Address:* ${wallet.publicKey}\nView your private key in Settings.`,
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
          `✅ *Wallet Recovered!*\n\n*Address:* ${wallet.publicKey}\nView your private key in Settings.`,
          { parse_mode: 'Markdown' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to recover wallet. Please check your recovery phrase and try again.');
      }
      ctx.session.awaitingRecoveryPhrase = false;
      return;
    }
    // ----- CASH BUY FLOW -----
    if (ctx.session.cashBuy) {
      // Step: entering phone number
      if (ctx.session.cashBuy.step === 'phoneNumber') {
        const phoneNumber = ctx.message.text.trim();
        if (!/^\d{9}$/.test(phoneNumber)) {
          await ctx.reply('❌ Invalid phone number. Please enter a valid 9-digit phone number:');
          return;
        }
        ctx.session.cashBuy.phoneNumber = phoneNumber;
        ctx.session.cashBuy.step = 'amount';
        await ctx.reply('💵 Enter the USD amount you wish to purchase:');
        return;
      } else if (ctx.session.cashBuy.step === 'amount') {
        const amount = parseFloat(ctx.message.text);
        if (isNaN(amount) || amount <= 0) {
          await ctx.reply('❌ Invalid amount. Please enter a valid USD amount:');
          return;
        }
        ctx.session.cashBuy.amount = amount;
        ctx.session.cashBuy.step = 'confirm';
        const fee = amount * 0.03;
        const netAmount = amount - fee;
        const solPrice = await getSolPrice();
        const solReceived = netAmount / solPrice;
        await ctx.reply(
          `💵 Amount: $${amount}\n💸 Fee (3%): $${fee.toFixed(2)}\n💰 Net: $${netAmount.toFixed(2)}\n🪙 ≈ ${solReceived.toFixed(4)} SOL\n\nProceed?`,
          {
            parse_mode: 'Markdown',
            ...Markup.inlineKeyboard([
              [{ text: '✅ Submit', callback_data: 'submit' }, { text: '❌ Cancel', callback_data: 'cancel_cash_buy' }]
            ])
          }
        );
        return;
      }
    }
    // ----- SEND FLOW (unchanged) -----
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
        if (isNaN(amountUSD) || amountUSD < 1) {
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
  } catch (error) {
    console.error('❌ Text Handler Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
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
    // Instead of editing the current message, create a new message
    await ctx.reply(
      `Using your SOL address:\n*${activeWallet.publicKey}*\n\nProcessing payment... ⏳`,
      {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '🔙 Cancel', callback_data: 'cancel_cash_buy' }]
          ]
        }
      }
    );
    // Waafi Preauthorization Request
    const { phoneNumber, amount, paymentMethod, solAddress } = ctx.session.cashBuy;
    const preauthBody = {
      schemaVersion: "1.0",
      requestId: Date.now().toString(),
      timestamp: new Date().toISOString(),
      channelName: "WEB",
      serviceName: "API_PREAUTHORIZE",
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        paymentMethod: "MWALLET_ACCOUNT",
        payerInfo: { accountNo: phoneNumber },
        transactionInfo: {
          referenceId: "ref" + Date.now(),
          invoiceId: "INV" + Date.now(),
          amount: amount,
          currency: "USD",
          description: "SOL Purchase Preauthorization"
        }
      }
    };
    console.log("Preauthorization Request Body:", preauthBody);
    const preauthResponse = await axios.post('https://api.waafipay.net/asm', preauthBody);
    console.log("Preauthorization Response:", preauthResponse.data);
    // Check if preauthorization approved; if not, show a custom error if errorCode is E10205.
    if (!(preauthResponse.data &&
          preauthResponse.data.params &&
          preauthResponse.data.params.state === "APPROVED")) {
      let errorMsg = preauthResponse.data.responseMsg || "Swap failed. We're sorry.";
      if (preauthResponse.data.errorCode === "E10205") {
        errorMsg = "haraygaag kugu ma filna";
      }
      await ctx.reply(`❌ ${errorMsg}`, { parse_mode: 'Markdown' });
      ctx.session.cashBuy = null;
      return;
    }
    const referenceId = preauthResponse.data.params.referenceId;
    const transactionId = preauthResponse.data.params.transactionId;
    const fee = amount * 0.03;
    const netAmountForConversion = amount - fee;
    // Execute Binance trade: buy SOL then withdraw.
    let result;
    try {
      result = await realTimeBuyAndWithdrawSOL(ctx, netAmountForConversion, solAddress);
    } catch (binanceError) {
      console.error("❌ Binance trade error:", binanceError);
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'Markdown' });
      ctx.session.cashBuy = null;
      return;
    }
    if (!result || !result.acquiredSol || result.acquiredSol <= 0) {
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'Markdown' });
      ctx.session.cashBuy = null;
      return;
    }
    // Commit preauthorization after successful SOL delivery
    const commitBody = {
      schemaVersion: "1.0",
      requestId: Date.now().toString(),
      timestamp: new Date().toISOString(),
      channelName: "WEB",
      serviceName: "API_PREAUTHORIZE_COMMIT",
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        referenceId,
        transactionId,
        description: "PREAUTH Commit for SOL Purchase"
      }
    };
    console.log("Commit Request Body:", commitBody);
    const commitResponse = await axios.post('https://api.waafipay.net/asm', commitBody);
    console.log("Commit Response:", commitResponse.data);
    if (commitResponse.data &&
        commitResponse.data.params &&
        commitResponse.data.params.state === "APPROVED") {
      await ctx.reply(
        `🎉 Congratulations! 🤝\nYour $EVC swap to SOL is complete.\nTransaction ID: ${result.withdrawalId}\n🔍 View on Solscan: https://solscan.io/tx/${result.withdrawalId}`,
        {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: '🔙 Back to Main', callback_data: 'back_to_main' }]
            ]
          }
        }
      );
    } else {
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'Markdown' });
    }
    ctx.session.cashBuy = null;
  } catch (error) {
    console.error("❌ Preauthorization Processing Error:", error);
    await ctx.reply("❌ Swap failed. We're sorry.", { parse_mode: 'Markdown' });
  }
});

bot.action('cancel_cash_buy', async (ctx) => {
  try {
    ctx.session.cashBuy = null;
    // Instead of editing the existing message, send a new message.
    await ctx.reply('❌ Transaction cancelled. Returning to main menu...', {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [{ text: '💰 Buy SOL', callback_data: 'cash_buy' },
           { text: '💸 Sell SOL', callback_data: 'sell' }]
        ]
      }
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Cash Buy Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

// ===== END OF CASH BUY FLOW =====

// ----- SEND FLOW & OTHER BOT ACTIONS (unchanged) -----
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
        ])
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

bot.action('help', async (ctx) => {
  await ctx.reply('Help info goes here...');
});

bot.action('settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ Settings Menu\n\n1. Private Key - View your wallet’s private key.\n2. Manage Wallet - Switch between wallets.\n3. Reset Wallet - Discard old wallet & create a new one.\n\n⚠️ NEVER share your private key!`,
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

bot.action('show_private_key', async (ctx) => {
  try {
    const disclaimerText = 
      `*Keep Your Private Key Secret*\n\n• Your Private Key gives full access to your funds.\n• NEVER share it with anyone.\n\nPress *Continue* to reveal your Private Key.`;
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

bot.action('confirm_show_private_key', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.');
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) return ctx.reply('❌ Private key not available. Please import your wallet.');
    const privateKeyMsg = `*Your Private Key*\n\n\`${storedPrivateKey}\`\n\n⚠️ Do not share this key with anyone.`;
    await ctx.editMessageText(privateKeyMsg, {
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([[Markup.button.callback('Done', 'back_to_settings')]])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ confirm_show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

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
    await ctx.editMessageText('🗄️ Select Wallet:\nChoose the wallet you wish to use:', {
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
    await ctx.reply('✅ Active wallet updated.');
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Select Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('back_to_settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ Settings Menu\n\n1. Private Key\n2. Manage Wallet\n3. Reset Wallet\n\n⚠️ NEVER share your private key!`,
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

bot.action('reset_wallet_prompt', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚠️ RESET WALLET\n\nAre you sure you want to reset your wallet? FARASbot will generate a new wallet for you and discard your old one. .\n*This action is irreversible!*`,
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
      `CONFIRM: Are you absolutely sure you want to reset your wallet?\nThis action cannot be undone!\nLast chance to cancel!`,
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
      `✅ Wallet Reset Successful!\n\nA new wallet has been created.\n*New Address:* \`${newWallet.publicKey}\`\nOld wallet discarded. Type /start to continue.`,
      {
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: [[{ text: '🔙 Back to Main Menu', callback_data: 'back_to_main' }]] }
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_final Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

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
        reply_markup: {
          inline_keyboard: [
            [{ text: '💰 Cash Buy', callback_data: 'cash_buy' },
             { text: '💸 Send SOL', callback_data: 'send' },
             { text: '📥 Receive SOL', callback_data: 'receive' }],
            [{ text: '🔄 Refresh Balance', callback_data: 'refresh' }],
            [{ text: '❓ Help', callback_data: 'help' },
             { text: '⚙️ Settings', callback_data: 'settings' }]
          ]
        }
      }
    );
  } catch (error) {
    console.error('❌ Back to Main Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.action('close_message', async (ctx) => {
  try {
    await ctx.reply('🎉 Transaction Completed Successfully!', { parse_mode: 'Markdown' });
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Close Message Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.');
  }
});

bot.launch()
  .then(() => console.log('🚀 Bot is live!'))
  .catch((error) => {
    console.error('❌ Bot Launch Error:', error);
  });

// Helper: Cancel preauthorization call
async function cancelPreauthorization(referenceId, transactionId) {
  try {
    const cancelBody = {
      schemaVersion: "1.0",
      requestId: Date.now().toString(),
      timestamp: new Date().toISOString(),
      channelName: "WEB",
      serviceName: "API_PREAUTHORIZE_CANCEL",
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        referenceId,
        transactionId,
        description: "Cancel Preauthorization for SOL Purchase"
      }
    };
    console.log("Cancel Request Body:", cancelBody);
    const cancelResponse = await axios.post('https://api.waafipay.net/asm', cancelBody);
    console.log("Cancel Response:", cancelResponse.data);
    return cancelResponse.data;
  } catch (error) {
    console.error("❌ Cancel Preauthorization Error:", error.response ? error.response.data : error);
    throw error;
  }
}
