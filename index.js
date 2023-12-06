import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";

import error from "./Error/error.js"
import adminRoutes from "./routes/admin/admins.js";
import userRoutes from "./routes/user/users.js";
import productRoutes from './routes/product/products.js'
import brandRoutes from "./routes/product/brands.js";
import categoryRoutes from "./routes/product/categories.js";
import reviewRoutes from "./routes/product/reviews.js";

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(helmet());

app.use(adminRoutes);
app.use(userRoutes);
app.use(brandRoutes);
app.use(categoryRoutes);
app.use(productRoutes);
app.use(reviewRoutes);

app.get("/", (req, res) => {
    res.send("You have reached to ecom server")
});

app.listen(process.env.PORT, () => {
    console.log(`Server is running at port ${process.env.PORT}`);
});

app.use(error)
