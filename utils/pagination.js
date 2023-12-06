export const getPaginationParams = (q) => {
    const page = q?.page ? +q.page : 1;
    const limit = q?.limit ? +q.limit : 10;
    const offset = (page - 1) * limit < 0 ? 0 : (page - 1) * limit;
    return { page, limit, offset };
}

export const sendPaginationResults = (page, limit, offset, count, rows) => {
    let totalPages = Math.ceil(count / limit);
    if (!totalPages) totalPages = 0;
    const response = {}
    response.page = page;
    response.limit = limit;
    response.count = count ? count : 0;
    response.totalPages = totalPages;
    response.rows = rows ? rows : [];
    return response;
} 