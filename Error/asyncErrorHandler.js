import ErrorHandler from "./errorHandler.js";
const asyncErrorHandler = (func) => (req, res, next) => 
   
    func(req, res, next).catch(err=> 
        next(new ErrorHandler("internal server error", 500, err)));


export default asyncErrorHandler