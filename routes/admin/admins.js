import express from "express";

import {
    adminSignIn,
    adminLogOut,
    adminRefreshTokens,
    adminAddRootAdmin,
    addNewAdmin,
    editAdmin,
    fetchAllRoles,
    fetchRole,
    addNewRole,
    editRole,
    deleteRole,
    deleteAdmin,
    fetchAllPermissions,
    fetchAllAdmins,
    fetchAdminDetails,
    resetPasswordForAdmin,
    changePasswordForSelf,
    viewAllCarts,
    viewAllOrders,
    viewAllUsers,

} from "../../controllers/admin/admins.js"

import requireAdminAuth from "../../middlewares/requireAdminAuth.js";

import {
    requireAdminPermission,
} from "../../middlewares/adminPermissions.js";
import { searchResult } from "../../utils/utils.js";

const router = express.Router();

router.post("/admin/root", adminAddRootAdmin);
router.post("/admin/signin", adminSignIn);
router.post("/admin/refresh", adminRefreshTokens);
router.post("/admin/logout", adminLogOut);

// manage admin routes
router.get("/admins", requireAdminAuth, requireAdminPermission, fetchAllAdmins);     
router.get("/admins/admin", requireAdminAuth, requireAdminPermission, fetchAdminDetails);    

router.post("/admin/new", requireAdminAuth, requireAdminPermission, addNewAdmin);

router.patch("/admin/edit", requireAdminAuth, requireAdminPermission, editAdmin);  
router.patch("/admin/password/reset", requireAdminAuth, requireAdminPermission, resetPasswordForAdmin);  
router.patch("/admin/password/self", requireAdminAuth, changePasswordForSelf);

router.delete("/admin/delete", requireAdminAuth, requireAdminPermission, deleteAdmin);   

// manage roles routes
router.get("/admin/roles", requireAdminAuth, requireAdminPermission, fetchAllRoles);  
router.get("/admin/roles/role", requireAdminAuth, requireAdminPermission, fetchRole); 

router.post("/admin/role/new", requireAdminAuth, requireAdminPermission, addNewRole);    

router.patch("/admin/role/edit", requireAdminAuth, requireAdminPermission, editRole);   

router.delete("/admin/role/delete", requireAdminAuth, requireAdminPermission, deleteRole);  

// view all permissions
router.get("/admin/permissions", requireAdminAuth, requireAdminPermission, fetchAllPermissions); 

// view all carts
router.get("/admin/carts", requireAdminAuth, requireAdminPermission, viewAllCarts);  

// view all orders
router.get("/admin/orders", requireAdminAuth, requireAdminPermission, viewAllOrders); 

//view all users
router.get("/admin/users", requireAdminAuth, requireAdminPermission, viewAllUsers);

// search for products, brands and categories
router.post('/search', searchResult);

export default router;