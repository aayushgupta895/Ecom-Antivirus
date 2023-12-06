import { db } from "../../models/index.js";
import { getPaginationParams, sendPaginationResults } from "../../utils/pagination.js";

export const fetchAllReviews = async (req, res) => {
    try {
        const q = req.query;
        let searchTerms = {};
        if (q.productId) searchTerms["productId"] = q.productId;
        if (q.isVerified) searchTerms["isVerified"] = q.isVerified;
        const { page, offset, limit } = getPaginationParams(req.query);

        const { count, rows } = await db.Review.findAndCountAll({
            where: searchTerms,
            offset,
            limit,
            include: {
                model: db.Product,
            }
        });

        const allReviews = rows.map(review => {
            return {
                "reviewId": review.reviewId,
                "review": review.review,
                "name": review.name,
                "email": review.email,
                "isVerified": review.isVerified,
                "productId": review.productId,
                "productName": review.product.name,
                "createadAt": review.createdAt,
                "updatedAt": review.updatedAt
            }
        })

        const response = sendPaginationResults(page, limit, offset, count, allReviews);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewReview = async (req, res) => {

    try {
        const { productId } = req.query;
        const { review, name, email } = req.body;

        // check for productId
        if (!productId) throw Error("ProductId not provided");

        const newReview = await db.Review.create({
            review, name, email, productId,
        });

        res.status(200).json("Review has been posted");
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const verifyReview = async (req, res) => {
    try {
        const { reviewId } = req.query;
        if (!reviewId) throw Error("ReviewId not provided");

        // check if unverified
        const unverifiedEmali = await db.Review.findOne({ where: { reviewId } });
        if (!unverifiedEmali) throw Error("Review does not exist")
        if (unverifiedEmali.isVerified) throw Error("Review already verified");

        // verify review
        unverifiedEmali.isVerified = true;
        unverifiedEmali.save();

        res.status(200).json(unverifiedEmali);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteReviews = async (req, res) => {
    try {
        let { reviewIds } = req.query;

        reviewIds = reviewIds.split(',');
        const reviews = reviewIds.map((rw)=>rw.trim());
        const deletedReviews = await db.Review.destroy({ where: { reviewId: reviews } })
            .catch(err => { throw Error(err) });

        res.status(200).json({"deleted rows are" : deletedReviews});

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}