import { db } from "../../models/index.js"
import { getPaginationParams, sendPaginationResults } from "../../utils/pagination.js";


export const fetchAllCategories = async (req, res) => {
    try {
        const { page, offset, limit } = getPaginationParams(req.query);

        // fetch all categories
        const { count, rows } = await db.Category.findAndCountAll({
            offset,
            limit
        });

        const response = sendPaginationResults(page, limit, offset, count, rows);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewCategory = async (req, res) => {
    try {
        const { name } = req.body;

        // create new category
        const newCategory = await db.Category.create({ name });
        res.status(200).json(newCategory);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const editCategory = async (req, res) => {
    try {
        const { categoryId } = req.query;
        const { name } = req.body

        if (!categoryId) throw Error("CategoryId not provided");

        // check if category exists
        const existingCategory = await db.Category.findOne({ where: { categoryId } });
        if (!existingCategory) throw Error("Category does not exist");

        // edit category
        existingCategory.name = name;
        await existingCategory.save();

        res.status(200).json(existingCategory);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteCategory = async (req, res) => {
    try {
        const { categoryId } = req.query;

        if (!categoryId) throw Error("CategoryId not provided");

        const category = await db.Category.findOne({ where: { categoryId } });

        if (!category) throw Error("Category does not exist");
        

        const isAvailable = await db.productBrandCategories.findOne({ where: { categoryId } });
        if (isAvailable) throw Error("Category is still in use");

        await category.destroy();
        res.status(200).json(category.categoryId);

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}