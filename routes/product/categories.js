import express from "express";

import {
    fetchAllCategories,
    addNewCategory,
    editCategory,
    deleteCategory
} from "../../controllers/product/categories.js"

import requireAdminAuth from "../../middlewares/requireAdminAuth.js";

import { requireProductPermission } from "../../middlewares/adminPermissions.js";

const router = express.Router();

router.get("/categories", fetchAllCategories);
router.post("/categories", requireAdminAuth, requireProductPermission, addNewCategory);
router.patch("/categories", requireAdminAuth, requireProductPermission, editCategory);
router.delete("/categories", requireAdminAuth, requireProductPermission, deleteCategory);

export default router;