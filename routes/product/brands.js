import express from "express";
import multer from "multer";

import {
    fetchAllBrands,
    addNewBrand,
    editBrandDetails,
    deleteBrand,
    getBrandDetails,
    updateBrandImage,
    deleteBrandImage
} from "../../controllers/product/brands.js";

import requireAdminAuth from "../../middlewares/requireAdminAuth.js";

import {
    requireProductPermission,
} from "../../middlewares/adminPermissions.js";

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const router = express.Router();

router.get("/brands", fetchAllBrands);
router.get("/brands/brand", getBrandDetails);
router.post("/brands", requireAdminAuth, requireProductPermission, upload.single("image"), addNewBrand);
router.patch("/brands/image", requireAdminAuth, requireProductPermission, upload.single("image"), updateBrandImage);   
router.delete("/brands/image", requireAdminAuth, requireProductPermission, deleteBrandImage);   
router.patch("/brands", requireAdminAuth, requireProductPermission, editBrandDetails);
router.delete("/brands", requireAdminAuth, requireProductPermission, deleteBrand);

export default router;