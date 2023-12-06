import { DataTypes } from "sequelize";

import { sequelize } from "../../dbconfig.js";

const Order = sequelize.define("order", { // this table will contains the information of purchased products
      orderId : {
         type : DataTypes.UUID,
         defaultValue : DataTypes.UUIDV4,
         primaryKey : true,
      },
      razorpay_orderId : {
         type : DataTypes.STRING,
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
      },
      razorpay_payment_id : {
         type : DataTypes.STRING,
         allowNull : false
      },
      razorpay_signature : {
         type : DataTypes.STRING,
         allowNull : false
      }, 
      paymentStatus : {
         type : DataTypes.STRING,
         defaultValue : "failed"
      }, 
      paymentFailedReason :{
         type : DataTypes.STRING,
         allowNull : false,
         defaultValue : "NA"
      }
   }
);

export default Order;

