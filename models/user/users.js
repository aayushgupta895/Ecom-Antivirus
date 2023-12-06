import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const User = sequelize.define("users", {
    userId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING(100),
        allowNull: false,
        unique: true,
        validate: {
            isEmail: true,
        }
    },
    phoneNo: {
        type: DataTypes.STRING(20),
        allowNull: false,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    city: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    state: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
},
    {
        indexes: [
            {
                unique: true,
                fields: ["email"]
            }
        ]
    }
);

export default User;

