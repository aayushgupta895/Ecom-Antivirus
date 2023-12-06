import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Category = sequelize.define('category', {
    categoryId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(50),
        allowNull: false,
    }
})

export default Category;