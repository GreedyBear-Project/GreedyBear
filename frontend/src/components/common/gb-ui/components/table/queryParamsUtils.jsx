/* This functions are used to serialize and deserialize URL params, to values for ordering and filter

Data in tables about filter and ordering are saved as object, but in the url is a string.
These funcitions helps to convert from obj to string and vice versa
*/

/**
 * This function is used to convert filters from obj to string
 * @argument {Array<Object>} filters
 * @return {Object}
 */
const serializeFilterParams = (filters) =>
  filters.reduce((acc, { id, value }) => ({ ...acc, [id]: value }), {});

/**
 * This function is used to convert filters from string to obj
 * @argument {Object} filters
 * @return {Array<Object>}
 */
const deserializeFilterParams = (filters) =>
  Array.from(
    Object.entries(filters).map(([filterKey, filterValue]) => ({
      id: filterKey,
      value: filterValue,
    })),
  );

/**
 * This function is used to convert ordering key from obj to string
 * @argument {Array<Object>} sortBy
 * @return {String}
 */
const serializeSortByParams = (sortBy) =>
  sortBy
    .map(({ id, desc }) => `${desc ? "-" : ""}${id.split("-")[0]}`)
    .join(",");

/**
 * This function is used to convert ordering key from string to obj
 * @argument {String} filters
 * @return {Array<Object>}
 */
const deserializeSortByParams = (sortByStr) =>
  Array.from(
    sortByStr.split(",").map((str) => ({
      id: str.charAt(0) === "-" ? str.slice(1) : str,
      desc: str.charAt(0) === "-",
    })),
  );

export {
  serializeFilterParams,
  deserializeFilterParams,
  serializeSortByParams,
  deserializeSortByParams,
};
