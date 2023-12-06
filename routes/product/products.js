import express from 'express';
import multer from "multer";

import {
    fetchAllProducts,
    fetchProductDetails,
    addNewProduct,
    updateProductImage,
    deleteProductImage,
    updateProductDetails,
    addNewProductKeys,
    editProductKey,
    getAllProductKeys,
    deleteProductKeys,
    deleteProducts
} from "../../controllers/product/products.js";

import requireAdminAuth from "../../middlewares/requireAdminAuth.js";

import { requireProductPermission, requireProductKeyPermission } from "../../middlewares/adminPermissions.js";

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const router = express.Router();

router.get("/products", fetchAllProducts);
router.get("/products/product", fetchProductDetails);

router.post("/products", requireAdminAuth, requireProductPermission, upload.single("image"), addNewProduct);

router.patch("/products/image", requireAdminAuth, requireProductPermission, upload.single("image"), updateProductImage);
router.patch("/products", requireAdminAuth, requireProductPermission, updateProductDetails);

router.delete("/products/image", requireAdminAuth, requireProductPermission, deleteProductImage);
router.delete("/products", requireAdminAuth, requireProductPermission, deleteProducts);

router.get("/products/product-keys", requireAdminAuth, requireProductKeyPermission, getAllProductKeys);
router.post('/products/product-keys', requireAdminAuth, requireProductKeyPermission, addNewProductKeys);
router.patch("/products/product-keys", requireAdminAuth, requireProductKeyPermission, editProductKey);
router.delete("/products/product-keys", requireAdminAuth, requireProductKeyPermission, deleteProductKeys);


export default router;