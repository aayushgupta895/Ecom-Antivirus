import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const lockedKeys = sequelize.define("lockedkey", { // this table will contains the information of purchased products
    id : {
        type : DataTypes.UUID,
        defaultValue : DataTypes.UUIDV4,
        primaryKey : true,
    },
    userId : {
        type: DataTypes.STRING,
        defaultValue: DataTypes.UUIDV4,
        allowNull : false
    },
    products : {
        type: DataTypes.ARRAY(DataTypes.JSONB),
        allowNull: false, 
        defaultValue : [] 
    },
    totalPrice : {
        type : DataTypes.INTEGER,
        allowNull : false
    }
});

export default lockedKeys;

