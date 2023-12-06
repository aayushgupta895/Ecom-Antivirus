import { db } from "../../models/index.js"
import { getPaginationParams, sendPaginationResults } from "../../utils/pagination.js";
import { getImageName } from "../../utils/utils.js";
import { putImage, deleteImage } from "../../utils/s3.js";
import asyncErrorHandler from "../../Error/asyncErrorHandler.js";

export const fetchAllBrands = async (req, res) => {
    try {
        const { page, offset, limit } = getPaginationParams(req.query);

        // fetch all brands
        const { count, rows } = await db.Brand.findAndCountAll(
            {
                offset,
                limit,
                order: [["updatedAt", "DESC"]]
            }
        );
        const response = sendPaginationResults(page, limit, offset, count, rows);

        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const getBrandDetails = async (req, res) => {
    try {
        const { brandId } = req.query;
        if (!brandId) throw Error("BrandId not provided");

        const brand = await db.Brand.findOne({ where: { brandId } });
        if (!brand) throw Error("Brand does not exist");

        res.status(200).json(brand);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewBrand = async (req, res) => {
    try {
        const { name, description } = req.body;

        let image = { imageName: "", imageURL: "" };
        if (req.file) {
            image = await putImage(getImageName(), req.file.buffer, req.file.mimetype);
        }
        const { imageName, imageURL } = image;

        // create new brand
        const newBrand = await db.Brand.create({ imageName, imageURL, name, description })
            .catch(async (error) => {
                if (imageName) {
                    await deleteImage(imageName);
                };
                throw Error("Error with adding brand");
            });

        res.status(200).json(newBrand);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const editBrandDetails = async (req, res) => {
    try {
        const { brandId } = req.query;
        const { name, description } = req.body

        if (!brandId) throw Error("BrandId not provided");

        // check if brand exisits
        const existingBrand = await db.Brand.findOne({ where: { brandId } });
        if (!existingBrand) throw Error("Brand does not exist");

        // edit values
        existingBrand.name = name;
        existingBrand.description = description;
        await existingBrand.save();

        res.status(200).json(existingBrand);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const updateBrandImage = asyncErrorHandler(async(req, res, next) =>{

    const { brandId } = req.query;
    if (!brandId) throw Error("BrandId not provided");

    // check if brand exisits
    const existingBrand = await db.Brand.findOne({ where: { brandId } });
    if (!existingBrand) throw Error("Brand does not exist");

    let imageName = existingBrand.imageName ? existingBrand.imageName : getImageName();
    await putImage(imageName, req.file.buffer, req.file.mimetype);

    res.status(200).json("Image updated successfully");

})

export const deleteBrandImage = asyncErrorHandler(async(req, res, next) =>{

    const { brandId } = req.query;
    if (!brandId) throw Error("BrandId not provided");

    // check if brand exisits
    const existingBrand = await db.Brand.findOne({ where: { brandId } });
    if (!existingBrand) throw Error("Brand does not exist");

    if (existingBrand.imageName) {
        await deleteImage(existingBrand.imageName);
        existingBrand.imageName = "";
        existingBrand.imageURL = "";
        await existingBrand.save();
    }

    res.status(200).json({
        productId: existingBrand.productId,
        imageName: existingBrand.imageName,
        imageURL: existingBrand.imageURL
    });
    
})

export const deleteBrand = async (req, res) => {
    try {
        const { brandId } = req.query;

        if (!brandId) throw Error("BrandId not provided");

        const brand = await db.Brand.findOne({ where: { brandId } });
        if (!brand) throw Error("Brand does not exist");

        const isAvailable = await db.productBrandCategories.findOne({ where: { brandId } });

        if (isAvailable) throw Error("Brand is in use");

        await brand.destroy();

        res.status(200).json({"deletedBrand" : brand.brandId});
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}