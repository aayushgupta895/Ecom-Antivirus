import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Brand = sequelize.define('brands', {
    brandId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    imageName: {
        type: DataTypes.STRING,
        defaultValue: "",
    },
    imageURL: {
        type: DataTypes.STRING,
        defaultValue: "",
    },
    name: {
        type: DataTypes.STRING(50),
        allowNull: false,
    },
    description: {
        type: DataTypes.STRING(500),
    }
})

export default Brand;