import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Cart = sequelize.define("cart", {
    cartId: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
    },
    products: {
        type: DataTypes.ARRAY(DataTypes.JSONB),
        defaultValue: []     // three fields are to be give productId, quantity, discount;
    },
});

export default Cart;