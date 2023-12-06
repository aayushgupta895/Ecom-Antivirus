import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Role = sequelize.define("roles", {
    roleId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(50),
        allowNull: false,
    },
},
    {
        indexes: [
            {
                unique: true,
                fields: ["name"]
            }
        ]
    }
);

export default Role;