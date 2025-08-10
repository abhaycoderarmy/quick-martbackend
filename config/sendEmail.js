import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  secure: false, // true for port 465, false for other ports
  auth: {
    user: "arlucky562@gmail.com",
    pass: "ygrxqkkfbkdqvvqz",
  },
});

async function sendEmail(sendTo, subject, html) { 
  const info = await transporter.sendMail({
    from: 'arlucky562@gmail.com', // sender address
    to: sendTo, // recipient address
    subject: subject, // Subject line
    html: html, // html body
  });
}

export default sendEmail;