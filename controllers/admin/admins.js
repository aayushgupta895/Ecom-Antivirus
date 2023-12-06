import validator from "validator";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { getPaginationParams, sendPaginationResults } from "../../utils/pagination.js";
import { db } from "../../models/index.js"
import { getRandomString } from "../../utils/utils.js";
import asyncErrorHandler from "../../Error/asyncErrorHandler.js";
import Razorpay from "razorpay";

export const adminAddRootAdmin = async (req, res) => {
    const { name, email, phoneNo, password } = req.body;
    try {

        // check if rootAdmin already exists
        const checkRootAdmin = await db.Admin.findAndCountAll({
            where: {
                isRoot: true,
            }
        });

        if (checkRootAdmin.count !== 0) throw Error("Root Admin already exists");

        // validate email
        if (!validator.isEmail(email)) throw Error("Invalid Email");

        // validate Phone Number
        if (!validator.isMobilePhone(phoneNo, ["en-IN"])) throw Error("Invalid Phone Number");

        // validate password - password length minimum 6 charachters
        if (password.length < 6) throw Error("Password too short");

        // validate password - password length maximum 20 charachters
        if (password.length > 20) throw Error("Password too long");

        const salt = bcrypt.genSaltSync(12);
        const hash = await bcrypt.hash(password, salt);

        const rootAdminRole = await db.Role.findOne({
            where: {
                name: "rootAdmin",
            }
        });

        const rootAdmin = await db.Admin.create({
            name, email, phoneNo,
            password: hash,
            isRoot: true,
            roleId: rootAdminRole.roleId,
        });


        res.status(200).json("Root Admin created successfully");

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const adminSignIn = async (req, res) => {
    const { email, password } = req.body;
    try {

        // validate email
        if (!validator.isEmail(email)) throw Error("Invalid Email");

        // check if admin exists
        const admin = await db.Admin.findOne({
            where: { email }
        });

        if (!admin) throw Error("Admin does not exist");

        // compare passwords
        const match = await bcrypt.compare(password, admin.password);

        if (!match) throw Error("Incorrect Password");

        // extract permissions
        const allPermissions = await db.Permission.findAll({
            include: {
                model: db.Role,
                required: true,
                attributes: [],
                through: {
                    attributes: [],
                    where: {
                        roleId: admin.roleId,
                    }
                }
            }
        });

        const adminPermissions = allPermissions.map((ap) => ap.name);

        // create access and refresh tokens
        let accessTokenTime = 1000 * 60 * 60 * 24;
        let refreshTokenTime = 1000 * 60 * 60 * 24 * 7;
        const accessToken = jwt.sign({ adminId: admin.adminId, roleId: admin.roleId }, process.env.ADMIN_ACCESS_TOKEN_SECRET, { expiresIn: String(accessTokenTime) });
        const refreshToken = jwt.sign({ adminId: admin.adminId, roleId: admin.roleId }, process.env.ADMIN_REFRESH_TOKEN_SECRET, { expiresIn: String(refreshTokenTime) });

        // add refresh token to redis
        await db.redisClient.set(admin.adminId, refreshToken, {
            "EX": 60 * 60 * 24 * 7,
        });

        res.status(200).json({
            name: admin.name,
            email: admin.email,
            phoneNo: admin.phoneNo,
            isRoot: true,
            permissions: adminPermissions,
            accessToken: accessToken,
            refreshToken: refreshToken,
        });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const adminRefreshTokens = async (req, res) => {
    try {

        const { authorization } = req.headers;

        if (!authorization) {
            return res.status(401).json({ error: "Refresh token required" });
        }

        const refreshToken = authorization.split(" ")[1];

        // check refresh token recieved
        if (!refreshToken) throw Error("Refresh token not found");

        // verify jwt and extract data
        const data = jwt.verify(refreshToken, process.env.ADMIN_REFRESH_TOKEN_SECRET);

        if (!data.adminId || !data.roleId) throw Error("Invalid refresh token");

        // check if refresh token for given adminId
        if (data.adminId) {
            const existingRefreshToken = await db.redisClient.get(data.adminId);
            if (!existingRefreshToken) throw Error("Refresh token expired");
            if (refreshToken !== existingRefreshToken) throw Error("Invalid refresh token");
        }

        // create access and refresh tokens
        let accessTokenTime = 1000 * 60 * 60 * 24;
        let refreshTokenTime = 1000 * 60 * 60 * 24 * 7;
        const accessToken = jwt.sign({ adminId: data.adminId, roleId: data.roleId }, process.env.ADMIN_ACCESS_TOKEN_SECRET, { expiresIn: String(accessTokenTime) });
        const newRefreshToken = jwt.sign({ adminId: data.adminId, roleId: data.roleId }, process.env.ADMIN_REFRESH_TOKEN_SECRET, { expiresIn: String(refreshTokenTime) });

        // add refresh token to redis
        await db.redisClient.set(data.adminId, newRefreshToken, {
            "EX": 60 * 60 * 24 * 7,
        });

        res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const adminLogOut = async (req, res) => {
    try {

        const { authorization } = req.headers;

        if (!authorization) {
            return res.status(401).json({ error: "Refresh token required" });
        }

        const refreshToken = authorization.split(" ")[1];

        // check refresh token recieved
        if (!refreshToken) throw Error("Refresh token not found");

        // verify jwt and extract data
        const data = jwt.verify(refreshToken, process.env.ADMIN_REFRESH_TOKEN_SECRET);

        if (!data.adminId || !data.roleId) throw Error("Invalid refresh token");

        // delete redis token
        if (data.adminId) {
            await db.redisClient.del(data.adminId);
        }

        res.status(200).json("Logged out successfully");

    } catch (error) {
        res.status(400).json({ error: error.messsage });
    }
}

export const fetchAllAdmins = async (req, res) => {
    try {
        const q = req.query;
        const searchTerms = {};
        if (q.roleId) searchTerms["roleId"] = q.roleId;
        const { page, offset, limit } = getPaginationParams(req.query);

        let { count, rows } = await db.Admin.findAndCountAll({
            where: searchTerms,
            offset, limit,
            include: {
                model: db.Role,
            }
        });

        const allAdmins = rows.map(admin => {
            return {
                adminId: admin.adminId,
                name: admin.name,
                email: admin.email,
                roleId: admin.roleId,
                roleName: admin.role.name,
            }
        });

        const response = sendPaginationResults(page, limit, offset, count, allAdmins);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const fetchAdminDetails = async (req, res) => {
    try {
        const { adminId } = req.query;
        if (!adminId) throw Error("AdminId not provided");

        const admin = await db.Admin.findOne({
            where: { adminId },
            include: {
                model: db.Role,
            }
        });

        if (!admin) throw Error("Admin does not exist");
        res.status(200).json({
            adminId: admin.adminId,
            email: admin.email,
            phoneNo: admin.phoneNo,
            roleId: admin?.roleId ? admin.roleId : null,
            roleName: admin.role?.name ? admin.role.name : "NO ROLE",
            createdAt: admin.createdAt
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewAdmin = async (req, res) => {
    const { name, email, phoneNo, roleId } = req.body;
    try {

        // validate email
        if (!validator.isEmail(email)) throw Error("Invalid Email");

        // validate Phone Number
        if (!validator.isMobilePhone(phoneNo, ["en-IN"])) throw Error("Invalid Phone Number");

        if (!roleId) throw Error("RoleId not provided");

        // generate and hash a random password
        const password = getRandomString(8);
        const salt = bcrypt.genSaltSync(12);
        const hash = await bcrypt.hash(password, salt);

        const admin = await db.Admin.create({
            name, email, phoneNo,
            password: hash,
            roleId: roleId,
        });

        // send back the email and password
        res.status(200).json(
            {
                email: admin.email,
                password
            }
        );
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const editAdmin = async (req, res) => {
    const { adminId } = req.query;
    const { name, phoneNo, roleId } = req.body;
    try {

        // fetch admin
        const admin = await db.Admin.findOne({
            where: {
                adminId,
            }
        });

        // check if admin exists
        if (!admin) throw Error("Admin does not exist");

        // check if admin is root
        if (admin.isRoot === true) throw Error("Root Admin cannot be edited");

        if (!name) throw Error("Name is required");
        if (!phoneNo) throw Error("PhoneNo is required");
        if (!validator.isMobilePhone(phoneNo, ["en-IN"])) throw Error("Invalid Phone Number");

        admin.name = name;
        admin.phoneNo = phoneNo;

        admin.roleId = roleId;

        // extract permissions
        const allPermission = await db.Permission.findAll({
            attributes: ["name"],
            include: {
                model: db.Role,
                attributes: [],
                required: true,
                through: {
                    attributes: [],
                    where: {
                        roleId: admin.roleId,
                    }
                }
            }
        });

        const adminPermissions = allPermission.map((ap) => ap.name);

        await admin.save();

        res.status(200).json({
            name: admin.name,
            email: admin.email,
            phoneNo: admin.phoneNo,
            isRoot: admin.isRoot,
            permissions: adminPermissions,
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const resetPasswordForAdmin = async (req, res) => {
    try {
        const { adminId } = req.query;

        if (!adminId) throw Error("AdminId not provided");

        const admin = await db.Admin.findOne({ where: { adminId } });

        if (!admin) throw Error("Admin does not exist");
        if (admin.isRoot) throw Error("Root Admin password cannot be reset");

        // generate and hash a random password
        const password = getRandomString(8);
        const salt = bcrypt.genSaltSync(12);
        const hash = await bcrypt.hash(password, salt);

        admin.password = hash;
        admin.save();

        res.status(200).json({
            email: admin.email,
            password: password,
        })
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const changePasswordForSelf = async (req, res) => {
    try {
        const { adminId, newPassword } = req.body;

        const admin = await db.Admin.findOne({ where: { adminId } });

        // generate and hash a random password
        const salt = bcrypt.genSaltSync(12);
        const hash = await bcrypt.hash(newPassword, salt);

        admin.password = hash;
        admin.save();

        res.status(200).json("Password changed successfully")

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const fetchAllRoles = async (req, res) => {
    try {
        const { page, offset, limit } = getPaginationParams(req.query);

        const { count, rows } = await db.Role.findAndCountAll({
            offset, limit
        });

        const response = sendPaginationResults(page, limit, offset, count, rows);
        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const fetchRole = async (req, res) => {
    try {
        const { roleId } = req.query;

        // find role
        const role = await db.Role.findOne({
            where: {
                roleId,
            },
            include: {
                model: db.Admin,
                attributes: { exclude: ["createdAt", "updatedAt", "password", "roleId", "phoneNo"] }
            }
        });

        if (!role) throw Error("Role does not exist");

        const rolePermissions = await db.Permission.findAll(
            {
                include: {
                    model: db.Role,
                    required: true,
                    attributes: [],
                    through: {
                        attributes: [],
                        where: {
                            roleId,
                        }
                    }
                }
            }
        );

        let response = {
            roleId: role.roleId,
            name: role.name,
            permissions: rolePermissions
        }

        response["admins"] = [];

        if (role.admins && role.admins.length !== 0) {
            response["admins"] = role.admins;
        }

        res.status(200).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const addNewRole = async (req, res) => {
    const { name, permissions } = req.body;
    try {
        const role = await db.Role.create({ name });
        if (permissions && permissions.length !== 0) {
            await role.addPermissions(permissions)
                .catch(async (error) => {
                    await role.destroy();
                    throw Error("Role could not be added");
                });
        }
        res.status(200).json(role);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const editRole = async (req, res) => {
    const { roleId } = req.query;
    const { name, permissions } = req.body;
    try {
        const role = await db.Role.findOne(
            { where: { roleId } }
        );
        if (role.name === "rootAdmin") throw Error("Cannot edit root admin detail");
        role.name = name;
        await role.removePermissions(await role.getPermissions());
        if (permissions && permissions.length !== 0) {
            await role.addPermissions(permissions)
        }
        await role.save();
        res.status(200).json(role);
    } catch (error) {
        res.status(200).json({ error: error.message });
    }
}

export const deleteRole = async (req, res) => {
    const { roleId } = req.query;
    try {

        // find role
        const role = await db.Role.findOne({
            where: {
                roleId
            },
            include: [
                db.Admin
            ]
        });

        // checks: if role exists, role id not root admin, role is not associated to any admin
        if (!role) throw Error("Role does not exist");
        if (role.name === "rootAdmin") throw Error("Root admin can not be deleted");
        if (!role.admins || role.admins.length !== 0) throw Error("Role is associated to Admins hence can not be deleted");

        // delete associations from join table
        await role.removePermissions(await role.getPermissions());
        await role.destroy();

        // return roleId
        res.status(200).json({" deletedRoleId " : role.roleId});
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const fetchAllPermissions = async (req, res) => {
    try {
        const allPermissions = await db.Permission.findAll();
        res.status(200).json(allPermissions);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const deleteAdmin = async (req, res) => {
    const { adminId } = req.query;
    try {
        if (!adminId) throw Error("AdminId not provided");

        const admin = await db.Admin.findOne({ where: { adminId } });

        if (!admin) throw Error("Admin does not exist");
        if (admin.isRoot) throw Error("Root admin cannot be deleted");

        await admin.destroy();

        res.status(200).json({"deletedAdmin" : adminId});
    } catch (error) {
        res.status(400).json({ error: error.message })
    }
}

export const viewAllOrders = asyncErrorHandler(async (req, res, next) => {

    const { page, offset, limit } = getPaginationParams(req.query);
    let { count, rows } = await db.Order.findAndCountAll({
        offset, limit,
    });
    const response = sendPaginationResults(page, limit, offset, count, rows);
    res.status(200).json(response);
    

})

export const viewAllCarts = asyncErrorHandler(async (req, res, next) => {

    // const allCarts = await db.Cart.findAll();
    const { page, offset, limit } = getPaginationParams(req.query);
    let { count, rows } = await db.Cart.findAndCountAll({
        offset, limit,
    });
    const response = sendPaginationResults(page, limit, offset, count, rows);
    res.status(200).json(response);

})

export const getAllTransactions = asyncErrorHandler(async (req, res, next) => {

    var razorpay = new Razorpay({ key_id: process.env.razorpay_id, key_secret: process.env.razorpay_secret })
    const payments = await razorpay.payments.all();
    const { page, offset, limit , count} = getPaginationParams(req.query);
    const response = sendPaginationResults(page, limit, offset, count, payments.items);
    res.status(200).json(response);

})


export const viewAllUsers = asyncErrorHandler(async (req, res, next)=>{
    const { page, offset, limit } = getPaginationParams(req.query);
    let { count, rows } = await db.User.findAndCountAll({
        offset, limit,
        include : [
            {
                model : db.Cart,
            },
            {
                model : db.Order,
            }

        ]
    });
    const response = sendPaginationResults(page, limit, offset, count, rows);
    res.status(200).json(response);
})