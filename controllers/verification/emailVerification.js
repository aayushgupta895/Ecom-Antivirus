import { sendOtpToEmail } from "../../utils/utils.js";


export const sendOtp = async (req, res, next) =>{
    await sendOtpToEmail(req, res, next);    
    res.send({
        message : "otp sent successfully"
    })
}



 
