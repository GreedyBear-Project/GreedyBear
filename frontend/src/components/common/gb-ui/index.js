export { default as ErrorAlert } from "./components/alerts/ErrorAlert";
export { default as CopyToClipboardButton } from "./components/buttons/CopyToClipboardButton";
export { default as IconButton } from "./components/buttons/IconButton";
export { default as PopupFormButton } from "./components/buttons/PopupFormButton";
export { default as ScrollToTopButton } from "./components/buttons/ScrollToTopButton";
export { default as ContentSection } from "./components/containers/ContentSection";
export { default as Loader } from "./components/containers/Loader";
export { default as LoadingBoundary } from "./components/containers/LoadingBoundary";
export { default as SmallInfoCard } from "./components/containers/SmallInfoCard";
export { default as Select } from "./components/form/Select";
export { default as BooleanIcon } from "./components/icons/BooleanIcon";
export { default as FallBackLoading } from "./components/misc/FallbackLoading";
export { default as Toaster } from "./components/misc/Toaster";
export { default as UserBubble } from "./components/misc/UserBubble";
export { confirm } from "./components/modals/ConfirmModal";
export { default as DropdownNavLink } from "./components/nav/DropdownNavLink";
export { default as NavLink } from "./components/nav/NavLink";
export { default as useDataTable } from "./components/table/useDataTable";
export { default as DateHoverable } from "./components/time/DateHoverable";
export { default as ElasticTimePicker } from "./components/time/ElasticTimePicker";
export { default as useAxiosComponentLoader } from "./hooks/useAxiosComponentLoader";
export { default as useTimePickerStore } from "./stores/useTimePickerStore";
export { default as useToastr } from "./stores/useToastr";
export { getRandomColorsArray } from "./utils";

import useToastr from "./stores/useToastr";

export const addToast = (...args) => useToastr.getState().addToast(...args);
