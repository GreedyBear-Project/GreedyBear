import React from "react";
import classnames from "classnames";

/**
 * @type {component}
 * @param props
 */
export default function UserBubble({
  userInfo,
  size = "sm",
  className = undefined,
  ...elProps
}) {
  const userInitials =
    userInfo?.first_name?.charAt(0).concat(userInfo?.last_name?.charAt(0)) ||
    userInfo?.username?.slice(0, 2);

  const bubbleClassName = React.useMemo(
    () =>
      classnames(
        "chat-bubble",
        {
          "chat-bubble-sm": size === "sm",
          "chat-bubble-xs": size === "xs",
          highlight: true,
        },
        className,
      ),
    [className, size],
  );

  return (
    <div
      {...elProps}
      aria-label="user menu bubble"
      title={userInfo?.full_name}
      className={bubbleClassName}
    >
      {userInitials}
    </div>
  );
}
