export function isObject(obj) {
  return typeof obj === "object" && obj !== null;
}

export function isEmptyObject(obj) {
  return !Object.keys(obj).length;
}

export function isFunction(func) {
  return typeof func === "function";
}

export function getObjectSubset(obj, keys) {
  return Object.fromEntries(
    Object.entries(obj).filter(([key]) => keys.includes(key)),
  );
}

function randomHSL() {
  return `hsla(${~~(360 * Math.random())},70%,70%,0.8)`;
}

function getRandomColor() {
  return `#${(0x1000000 + Math.random() * 0xffffff).toString(16).substr(1, 6)}`;
}

export function getRandomColorsArray(len = 10, hsl = false) {
  return Array.from({ length: len }, hsl ? randomHSL : getRandomColor);
}

export function readFileAsync(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      resolve(reader.result);
    };
    reader.onerror = reject;
    reader.readAsBinaryString(file);
  });
}

export function objToString(obj) {
  const stringify = (key, val) =>
    typeof val === "object"
      ? Object.entries(val).map(([k, v]) =>
          stringify(Number.isNaN(k) ? `${key}.${k}` : `${key}[${k}]`, v),
        )
      : `${key}: ${val}`;
  return Object.entries(obj).reduce(
    (str, [key, val]) => `${str}${stringify(key, val)}\n`,
    "",
  );
}

export function uniq(arr) {
  return arr.filter((x, i, a) => a.indexOf(x) === i);
}

export function diff(arr1, arr2, accesorFn = (d) => d) {
  return arr1.filter((x) => arr2.indexOf(accesorFn(x)) < 0);
}
