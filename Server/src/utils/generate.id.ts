const generateRandomId = (length: number): string => {
  return Math.random()
    .toString(36)
    .substring(2, length + 2);
};

export const GenerateId = (identifier?: string, length = 12): string => {
  return identifier
    ? `${identifier}_${generateRandomId(length)}`
    : generateRandomId(length);
};
