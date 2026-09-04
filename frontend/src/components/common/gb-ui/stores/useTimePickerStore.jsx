import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

// constants
const DEFAULT_RANGE_DATEFORMAT_MAP = {
  "6h": "dd/MM, HH:mm",
  "24h": "dd/MM, HH:mm",
  "7d": "do MMM",
  "3M": "MMM/yyyy",
  "6M": "MMM/yyyy",
  "1Y": "yyyy",
  "2Y": "yyyy",
};

// store
const useTimePickerStore = create(
  persist(
    (set, get) => ({
      RANGE_DATEFORMAT_MAP: DEFAULT_RANGE_DATEFORMAT_MAP,
      range: "24h",
      fromTimeIsoStr: null,
      dateFormat: DEFAULT_RANGE_DATEFORMAT_MAP["24h"],
      onTimeIntervalChange: (range, fromTimeIsoStr) => {
        set({
          range,
          fromTimeIsoStr,
          dateFormat: get().RANGE_DATEFORMAT_MAP[range],
        });
      },
    }),
    {
      name: "gbUI-useTimePickerStore", // unique name
      storage: createJSONStorage(() => localStorage),
    },
  ),
);

export default useTimePickerStore;
