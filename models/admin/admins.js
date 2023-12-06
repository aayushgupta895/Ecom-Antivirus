import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Admin = sequelize.define("admins", {
    adminId: {
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
    },
    phoneNo: {
        type: DataTypes.STRING(20),
        allowNull: false,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    isRoot: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    }
},
    {
        indexes: [
            {
                unique: true,
                fields: ["email"]
            }
        ]
    })

export default Admin;