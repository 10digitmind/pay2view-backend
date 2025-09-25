const nodemailer = require('nodemailer');
const path = require('path');

async function createTransporter() {
  const hbs = await import('nodemailer-express-handlebars'); // dynamic import

  const transporter = nodemailer.createTransport({
    host: 'mail.privateemail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  transporter.use(
    'compile',
    hbs.default({ // note the `.default` when importing ESM
      viewEngine: {
        partialsDir: path.resolve('./views/'),
        defaultLayout: false
      },
      viewPath: path.resolve('./views/'),
      extName: '.hbs'
    })
  );

  return transporter;
}

module.exports = createTransporter;
