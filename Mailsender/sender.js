const createTransporter = require("../Nodemailer/nodemailer");

async function sendVerificationEmail(userEmail, userName, token) {
  const transporter = await createTransporter();
  const verificationUrl = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: "Verify Your Email",
    template: "verifyEmail", // template name without extension
    context: {
      name: userName,
      verificationUrl,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${userEmail}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

async function sendPasswordResetEmail(userEmail, userName, resetUrl) {
  const transporter = await createTransporter();

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: "Password reset  request",
    template: "resetEmail", // template name without extension
    context: {
      name: userName,
      resetUrl,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`password reset email sent to ${userEmail}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

async function sendPaymentAlertToCreator(
  userEmail,
  creatorName,
  contentTitle,
  amount,
  dashboardUrl
) {
  const transporter = await createTransporter();

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: "Congratulations Your content has been sold !!!",
    template: "VerifyPaymentToCreator", // template name without extension
    context: {
      creatorName,
      contentTitle,
      amount,
      dashboardUrl,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`payment verification sent to creator ${userEmail}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

async function sendPaymentAlertToBuyer(

  buyerName,
  contentTitle,
  contentUrl,
    buyerEmail,
) {
  const transporter = await createTransporter();

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: buyerEmail,
    subject: " Congratulations Content Unlocked !!!",
    template: "BuyerPaymentAlert", // template name without extension
    context: {
      buyerName,
      contentTitle,
      contentUrl,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`payment verification sent to buyer  ${buyerEmail}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

async function sendWithdrawalEmail(
  accountName,
  bankName,
  accountNumber,
  amount,
  userEmail
) {
  const transporter = await createTransporter();

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: " Withdrawal Request Received ✅ !!!",
    template: "WithdrawalRequest", // template name without extension
    cc: "withdrawalrequest@pay2view.com",
    context: {
      accountName,
      bankName,
      accountNumber,
      amount,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`payment verification sent to buyer  ${userEmail}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

async function contactEmail(fullname, email, subject, message, category) {
  const transporter = await createTransporter();

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "hello@pay2view.io",
    subject: subject,
    template: "contact", // template name without extension

    context: {
      fullname,
      email,
      subject,
      message,
      category,
    },
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`contact eail sent by   ${email}`);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendPaymentAlertToCreator,
  sendPaymentAlertToBuyer,
  sendWithdrawalEmail,
  contactEmail,
};
