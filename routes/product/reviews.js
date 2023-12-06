import express from "express";

import {
    fetchAllReviews,
    addNewReview,
    verifyReview,
    deleteReviews,
} from "../../controllers/product/reviews.js";

import requireAdminAuth from "../../middlewares/requireAdminAuth.js";

import { requireReviewPermission } from "../../middlewares/adminPermissions.js";

const router = express.Router();

router.get("/products/reviews", requireAdminAuth, requireReviewPermission, fetchAllReviews);

router.post("/products/reviews", addNewReview);
router.patch("/products/reviews/verify", requireAdminAuth, requireReviewPermission, verifyReview);
router.delete("/products/reviews", requireAdminAuth, requireReviewPermission, deleteReviews);

export default router;