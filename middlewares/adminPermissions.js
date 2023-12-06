export const requireAdminPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("admins")) {
            next();
        } else {
            throw Error("Not authorized to access admins");
        }
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
}

export const requireProductPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("products")) {
            next();
        } else {
            throw Error("Not authorized to access products");
        }
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
}

export const requireProductKeyPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("productKeys")) {
            next();
        } else {
            throw Error("Not authorized to access product keys");
        }
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
}

export const requireReviewPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("reviews")) {
            next();
        } else {
            throw Error("Not authorized to access reviews");
        }
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
}

export const requireOrderPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("orders")) {
            next();
        } else {
            throw Error("Not authorized to view orders");
        }
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
}

export const requireCartPermission = (req, res, next) => {
    const { adminPermissions } = req.body;
    try {
        if (adminPermissions.includes("carts")) {
            next();
        } else {
            throw Error("Not authorized to access carts");
        }
    } catch (error) {
        res.status.json({ error: error.message });
    }
}