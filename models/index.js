import { DataTypes } from "sequelize";
import bcrypt from "bcrypt";

import { sequelize, redisClient } from "../dbconfig.js";
import { getRandomString } from "../utils/utils.js";

import Admin from "./admin/admins.js";
import Role from "./admin/roles.js";
import Permission from "./admin/permissions.js";
import User from "./user/users.js";
import Product from './product/products.js'
import ProductKey from './product/productKeys.js'
import Brand from './product/brands.js'
import Category from "./product/categories.js";
import Review from "./product/reviews.js";
import Cart from "./order/carts.js";
import Order from "./order/orders.js";

// Role > Admin
Role.hasMany(Admin, { foreignKey: "roleId" });
Admin.belongsTo(Role, { foreignKey: "roleId" })

// Role <> Permission
Role.belongsToMany(Permission, { through: "rolePermissions", foreignKey: "roleId" });
Permission.belongsToMany(Role, { through: "rolePermissions", foreignKey: "permissionId" });

// Product > ProductKey
Product.hasMany(ProductKey, { foreignKey: "productId", onDelete: "cascade" });
ProductKey.belongsTo(Product, { foreignKey: "productId" });

// Product > Review
Product.hasMany(Review, { foreignKey: "productId", onDelete: "cascade" });
Review.belongsTo(Product, { foreignKey: "productId" });

Order.hasMany(ProductKey, { foreignKey: "orderId" });
ProductKey.belongsTo(Order, { foreignKey: "orderId" });



const productBrandCategories = sequelize.define("productBrandCategories", {
    brandId: {
        type: DataTypes.UUID,
        references: {
            model: Brand,
            key: "brandId",
        },
        primaryKey: true,
    },
    categoryId: {
        type: DataTypes.UUID,
        references: {
            model: Category,
            key: "categoryId",
        },
        primaryKey: true,
    },
    productId: {
        type: DataTypes.UUID,
        references: {
            model: Product,
            key: "productId",
        },
        primaryKey: true,
    },
});

Product.hasOne(productBrandCategories, { foreignKey: "productId" });
productBrandCategories.belongsTo(Product, { foreignKey: "productId" });

Brand.hasMany(productBrandCategories, { foreignKey: "brandId" });
productBrandCategories.belongsTo(Brand, { foreignKey: "brandId" });

Category.hasMany(productBrandCategories, { foreignKey: "categoryId" });
productBrandCategories.belongsTo(Category, { foreignKey: "categoryId" });

User.hasOne(Cart, { foreignKey: "userId" });
Cart.belongsTo(User, { foreignKey: "userId" });

User.hasMany(Order, { foreignKey : "userId" });
Order.belongsTo(User, { foreignKey : "userId" });

await sequelize.sync({ alter: true });

// set default permissions and roles
// const allPermissions = await Permission.bulkCreate([
//     { name: "admins", scope: "admin" },
//     { name: "products", scope: "product" },
//     { name: "productKeys", scope: "productKey" },
//     { name: "carts", scope: "cart" },
//     { name: "orders", scope: "order" },
//     { name: "reviews", scope: "review" },
// ]);

// const rootAdminRole = await Role.create({
//     name: "rootAdmin",
// });

// await rootAdminRole.addPermissions(allPermissions);

export const db = {
    sequelize,
    redisClient,
    Admin,
    Role,
    Permission,
    User,
    ProductKey,
    Product,
    Brand,
    Category,
    productBrandCategories,
    Review,
    Cart,
    Order,

};