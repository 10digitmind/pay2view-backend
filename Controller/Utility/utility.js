import crypto from 'crypto'

// Use a 32-byte key stored in .env
const algorithm = 'aes-256-cbc';
const key = Buffer.from(process.env.IMAGE_ENCRYPTION_KEY, 'hex'); // store as hex in .env

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    content: encrypted
  };
}

function decrypt(encrypted) {
  const decipher = crypto.createDecipheriv(
    algorithm,
    key,
    Buffer.from(encrypted.iv, 'hex')
  );
  let decrypted = decipher.update(encrypted.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
// utils/cloudflare.js

export const uploadToCloudflare = async (fileBuffer, fileName) => {
  const response = await axios.post(
    `https://api.cloudflare.com/client/v4/accounts/${process.env. CLOUDFLARE_ID}/stream`,
    fileBuffer,
    {
      headers: {
        Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
        "Content-Type": "application/octet-stream",
      },
      params: {
        "upload": "true",
        "fileName": fileName,
      },
    }
  );

  return response.data.result.uid; // Cloudflare video ID
};


function emailsToArray(emailString) {
  // Split by newlines, remove empty lines and trim spaces
  return emailString
    .split(/\r?\n/)           // split on newline (works on Windows/Linux)
    .map(email => email.trim()) // remove extra spaces
    .filter(email => email);   // remove empty strings
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}






// Batch sender
async function sendMarketingEmails(emailString, batchSize = 10, delayMs = 5000) {
  const emails = emailsToArray(emailString);

  for (let i = 0; i < emails.length; i += batchSize) {
    const batch = emails.slice(i, i + batchSize);

    // Send all emails in batch concurrently
    await Promise.all(
      batch.map(async email => {
        try {
          await Test(email); // your email send function
          console.log(`Email sent to ${email}`);
        } catch (err) {
          console.error(`Failed to send email to ${email}:`, err.message);
        }
      })
    );

    console.log(`Batch ${i / batchSize + 1} sent.`);

    // Wait before next batch
    if (i + batchSize < emails.length) {
      await delay(delayMs);
    }
  }

  console.log('All emails processed!');
}




module.exports = { encrypt, decrypt,uploadToCloudflare };