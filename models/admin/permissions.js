import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Permission = sequelize.define("permissions", {
    permissionId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true,
    },
    scope: {
        type: DataTypes.STRING(50),
        allowNull: false,
    }
},
    {
        indexes: [
            {
                unique: true,
                fields: ["name"]
            }
        ],
        timestamps: false,
    }
);

export default Permission;