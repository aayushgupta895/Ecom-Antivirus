import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const ProductKey = sequelize.define("productKeys", {
    productKeyId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    productKey: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    isSold: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    }
});

export default ProductKey;