import dotenv from "dotenv";
dotenv.config();

import ErrorHandler from '../../Error/errorHandler.js'
import asyncErrorHandler from '../../Error/asyncErrorHandler.js'
import { db } from "../../models/index.js";
import { getImageName } from "../../utils/utils.js";
import { putImage, deleteImage } from "../../utils/s3.js";
import { getPaginationParams, sendPaginationResults } from "../../utils/pagination.js";


export const fetchAllProducts = async (req, res) => {
    try {
        const q = req.query;
        let searchTerms = {};
        if (q.categoryId) searchTerms["categoryId"] = q.categoryId;
        if (q.brandId) searchTerms["brandId"] = q.brandId;
        const { page, offset, limit } = getPaginationParams(req.query);

        let { count, rows } = await db.Product.findAndCountAll({
            attributes: { exclude: ["createdAt", "updatedAt"] },
            offset,
            limit,
            include: {
                model: db.productBrandCategories,
                where: searchTerms,
                attributes: ["brandId", "categoryId"]
            }
        });

        const allProducts = rows.map((product) => {
            return {
                productId: product.productId,
                imageName: product.imageName,
                imageURL: product.imageURL,
                name: product.name,
                description: product.description,
                marketPrice: product.marketPrice,
                actualPrice: product.actualPrice,
                brandId: product.productBrandCategory.brandId,
                categoryId: product.productBrandCategory.categoryId,
            }
        });

        const response = sendPaginationResults(page, limit, offset, count, allProducts);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const fetchProductDetails = async (req, res) => {
    try {
        const { productId } = req.query;

        if (!productId) throw Error("ProductId not provided");

        const fetchedProduct = await db.Product.findOne(
            {
                where: { productId: productId },
                attributes: { exclude: ["createdAt", "updatedAt"] },
                include: [
                    {
                        model: db.productBrandCategories,
                        attributes: ["brandId", "categoryId"],
                        include: [
                            {
                                model: db.Brand,
                                attributes: ["name"],
                            },
                            {
                                model: db.Category,
                                attributes: ["name"],
                            }
                        ]
                    },
                    {
                        model: db.Review,
                        required: false,
                        attributes: { exclude: ["isVerified", "productId"] },
                        where: {
                            isVerified: true,
                        }
                    }
                ]
            }
        );

        if (!fetchedProduct) throw Error("Product does not exist");

        res.status(200).json({
            productId: fetchedProduct.productId,
            imageName: fetchedProduct.imageName,
            imageURL: fetchedProduct.imageURL,
            name: fetchedProduct.name,
            marketPrice: fetchedProduct.marketPrice,
            actualPrice: fetchedProduct.actualPrice,
            inStock: fetchedProduct.inStock,
            brandName: fetchedProduct.productBrandCategory.brand.name,
            categoryName: fetchedProduct.productBrandCategory.category.name,
            reviews: fetchedProduct.reviews,
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewProduct = async (req, res) => {
    
    try {
        
        const { name, description, marketPrice, actualPrice, brandId, categoryId, productKeys } = req.body;
        // check if brand and category are provided
        if (!brandId) throw Error("BrandId not provided");
        if (!categoryId) throw Error("categoryId not provided");

        // process image if provided
        let image = { imageName: "", imageURL: "" };
        if (req.file) {
            image = await putImage(getImageName(), req.file.buffer, req.file.mimetype);
        }
        const { imageName, imageURL } = image;

        // create new product
        const newProduct = await db.Product.create({
            imageName, imageURL, name, description, marketPrice, actualPrice,
        }).catch(async (error) => {
            if (imageName) {
                await deleteImage(imageName);
            };
            throw Error("Error with adding products");
        });

        // associate brand and categories to the product
        const pbc = await db.productBrandCategories.create({
            brandId, categoryId, productId: newProduct.productId,
        }).catch(async (error) => {
            if (newProduct.imageName) {
                await deleteImage(newProduct.imageName);
            };
            await newProduct.destroy();
            throw Error("Error with while adding brand and categories")
        });

        // add productKeys if provided
        if (productKeys && productKeys.length !== 0) {
            const keysToInsert = productKeys.map((prodk) => {
                return { productKey: prodk, productId: newProduct.productId }
            });
            await db.ProductKey.bulkCreate(keysToInsert)
                .then(async (productKeys) => {
                    let count = 0;
                    for (let pk of productKeys) count += 1
                    newProduct.inStock = count;
                    await newProduct.save();
                })
                // manual rollback
                .catch(async (error) => {
                    if (newProduct.imageName) {
                        await deleteImage(newProduct.imageName);
                    }
                    await newProduct.destroy();
                    throw Error("Error with Product Keys")
                });
        }

        const response = {
            productId: newProduct.productId,
            imageName: newProduct.imageName,
            imageURL: newProduct.imageURL,
            name: newProduct.name,
            description: newProduct.description,
            marketPrice: newProduct.marketPrice,
            actualPrice: newProduct.actualPrice,
            inStock: newProduct.inStock,
            brandId: pbc.brandId,
            categoryId: pbc.categoryId,
        };

        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const updateProductImage = async (req, res) => {
    try {
        const { productId } = req.query;
        if (!productId) throw Error("ProductId not provided");

        const fetchedProduct = await db.Product.findOne({
            where: { productId: productId },
        });

        if (!fetchedProduct) throw Error("Product does not exist");

        let imageName = fetchedProduct.imageName ? fetchedProduct.imageName : getImageName();
        await putImage(imageName, req.file.buffer, req.file.mimetype);

        res.status(200).json("Image updated successfully");
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteProductImage = async (req, res) => {
    try {
        const { productId } = req.query;
        if (!productId) throw Error("ProductId not provided");

        const fetchedProduct = await db.Product.findOne({
            where: { productId: productId },
        });

        if (!fetchedProduct) throw Error("Product does not exist");

        if (fetchedProduct.imageName) {
            await deleteImage(fetchedProduct.imageName);
            fetchedProduct.imageName = "";
            fetchedProduct.imageURL = "";
            await fetchedProduct.save();
        }

        res.status(200).json({
            productId: fetchedProduct.productId,
            imageName: fetchedProduct.imageName,
            imageURL: fetchedProduct.imageURL
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const updateProductDetails = async (req, res) => {
    try {
        const { productId } = req.query;
        const { name, description, marketPrice, actualPrice, brandId, categoryId } = req.body;
        if (!productId) throw Error("ProductId not provided");

        const fetchedProduct = await db.Product.findOne(
            {
                where: { productId: productId },
                attributes: { exclude: ["createdAt", "updatedAt"] },
                include: [
                    {
                        model: db.productBrandCategories,
                        attributes: ["brandId", "categoryId"],
                        include: [
                            {
                                model: db.Brand,
                                attributes: ["name"],
                            },
                            {
                                model: db.Category,
                                attributes: ["name"],
                            }
                        ]
                    }
                ]
            }
        );


        if (!fetchedProduct) throw Error("Product does not exist");

        fetchedProduct.name = name;
        fetchedProduct.description = description;
        fetchedProduct.marketPrice = marketPrice;
        fetchedProduct.actualPrice = actualPrice;

        let updateBrandCategory = {
            brandId: fetchedProduct.productBrandCategory.brandId,
            categoryId: fetchedProduct.productBrandCategory.categoryId,
            brand: fetchedProduct.productBrandCategory.brand,
            category: fetchedProduct.productBrandCategory.category,
        }
        let isChanged = false;

        if (updateBrandCategory.brandId !== brandId) {
            updateBrandCategory["brandId"] = brandId;
            isChanged = true;
        }

        if (updateBrandCategory.categoryId !== categoryId) {
            updateBrandCategory["categoryId"] = categoryId;
            isChanged = true;
        }

        if (isChanged) {
            await db.productBrandCategories.update(
                {
                    brandId: updateBrandCategory.brandId,
                    categoryId: updateBrandCategory.categoryId,
                },
                {
                    where: {
                        productId: fetchedProduct.productId
                    }
                });
            updateBrandCategory["brand"] = await db.Brand.findOne({ where: { brandId: updateBrandCategory.brandId } });
            updateBrandCategory["category"] = await db.Category.findOne({ where: { categoryId: updateBrandCategory.categoryId } });
        }

        await fetchedProduct.save();

        res.status(200).json({
            productId: fetchedProduct.productId,
            imageName: fetchedProduct.imageName,
            imageURL: fetchedProduct.imageURL,
            name: fetchedProduct.name,
            marketPrice: fetchedProduct.marketPrice,
            actualPrice: fetchedProduct.actualPrice,
            brandName: updateBrandCategory.brand.name,
            categoryName: updateBrandCategory.category.name,
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const getAllProductKeys = async (req, res) => {
    try {
        const { productId } = req.query;
        if (!productId) throw Error("ProductId not provided");

        const q = req.query;
        const searchTerms = {};
        searchTerms["productId"] = productId;
        if (q.isSold) searchTerms["isSold"] = q.isSold;
        const { page, offset, limit } = getPaginationParams(req.query);

        const { count, rows } = await db.ProductKey.findAndCountAll({
            where: searchTerms,
            offset, limit
        })

        const response = sendPaginationResults(page, limit, offset, count, rows);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const editProductKey = async (req, res) => {
    try {
        const { productKeyId } = req.query;
        const { productKey } = req.body;

        if (!productKeyId) throw Error("ProductKeyId not prodvided");
        const existingProductKey = await db.ProductKey.findOne({ where: { productKeyId } });

        if (!existingProductKey) throw Error("Product Key does not exist");
        if (existingProductKey.orderId) throw Error("Product Key cannot be changed");

        existingProductKey.productKey = productKey;

        await existingProductKey.save();

        res.status(200).json(existingProductKey);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteProductKeys = async (req, res) => {
    try {
        let { productKeyIds, productId } = req.query;
        productKeyIds = productKeyIds.split(',');
        const productKeyId = productKeyIds.map(pr=>pr.trim());

        const rows = await db.ProductKey.destroy({
            where : {
                productId,
                productKeyId,
                orderId : null,
            }
        });

        const product = await db.Product.findOne({ where : { productId }});
        product.inStock -= rows;
        await product.save();

        res.status(200).json({"rows deleted" : rows});

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}


export const addNewProductKeys = async (req, res) => {
    try {

        const { productId } = req.query;
        const { productKeys } = req.body;

        if (!productId) throw Error("ProductId does not exist");

        const product = await db.Product.findOne({ where: { productId: productId } });

        if (!product) throw Error("Product does not exist");
        if (!productKeys || productKeys.length == 0) throw Error("Product keys not provided");

        const inputPk = productKeys.map(pk => {
            return { productKey: pk, productId: product.productId }
        });

        const newProductKeys = await db.ProductKey.bulkCreate(inputPk);

        if (!newProductKeys) throw Error("Product keys not added");

        product.inStock += newProductKeys.length;
        product.save();

        res.status(200).json(newProductKeys);

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteProducts = async (req, res) => {
    try {
        let { productIds } = req.query;

        productIds = productIds.split(',');
        productIds = productIds.map((pr)=>pr.trim());
        const rows = await db.Product.destroy({ where: { productId: productIds } })
            .catch(err => { throw Error(err) });

        res.status(200).json({
            "deleted rows are " : rows
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}