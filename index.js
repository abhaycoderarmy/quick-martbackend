import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import morgan from 'morgan';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import connectDB from './config/connectDB.js';
import userRouter from './routes/user.route.js';
import categoryRouter from './routes/category.route.js';
import uploadRouter from './routes/upload.route.js';
import subCategoryRouter from './routes/subCategory.route.js';
import productRouter from './routes/product.route.js';
import cartRouter from './routes/cart.route.js';
import addressRouter from './routes/address.route.js';
import orderRouter from './routes/order.route.js';


dotenv.config();

const app = express();

app.use(cors({
  origin: '*',
  credentials: true
}));


app.use(express.json());
app.use(bodyParser.json());
app.use(morgan());
app.use(helmet({
    crossOriginResourcePolicy: false // if fronted is in different domain it will show error 
}));

app.use(cookieParser());


const PORT = process.env.PORT || 8080;

app.get('/', (req, res) => {
    res.send('An QuickMart Web is running');
});

app.use('/api/user', userRouter);
app.use('/api/category', categoryRouter);
app.use('/api/file', uploadRouter);
app.use('/api/subcategory', subCategoryRouter);
app.use('/api/product', productRouter);
app.use('/api/cart', cartRouter);
app.use('/api/address', addressRouter);
app.use('/api/order', orderRouter);

connectDB();

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});