import React from "react";
import "@testing-library/jest-dom";
import { render, screen, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ScrollToTopButton from "../../../src/components/common/gb-ui/components/buttons/ScrollToTopButton";

describe("ScrollToTopButton", () => {
  beforeEach(() => {
    Object.defineProperty(window, "scrollY", {
      value: 0,
      writable: true,
      configurable: true,
    });
    window.scrollTo = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("renders button with accessible name 'Scroll to top' when visible", () => {
    render(<ScrollToTopButton defaultVisible={true} scrollYOffset={-1} />);

    expect(
      screen.getByRole("button", { name: /scroll to top/i }),
    ).toBeInTheDocument();
  });

  test("is not visible by default when page is at the top", () => {
    render(<ScrollToTopButton />);

    expect(
      screen.queryByRole("button", { name: /scroll to top/i }),
    ).not.toBeInTheDocument();
  });

  test("becomes visible when scrolling past scrollYOffset", () => {
    render(<ScrollToTopButton scrollYOffset={300} />);

    expect(
      screen.queryByRole("button", { name: /scroll to top/i }),
    ).not.toBeInTheDocument();

    act(() => {
      window.scrollY = 350;
      fireEvent.scroll(window);
    });

    expect(
      screen.getByRole("button", { name: /scroll to top/i }),
    ).toBeInTheDocument();
  });

  test("hides again when scrolling back to the top", () => {
    render(<ScrollToTopButton scrollYOffset={300} />);

    act(() => {
      window.scrollY = 350;
      fireEvent.scroll(window);
    });

    expect(
      screen.getByRole("button", { name: /scroll to top/i }),
    ).toBeInTheDocument();

    act(() => {
      window.scrollY = 100;
      fireEvent.scroll(window);
    });

    expect(
      screen.queryByRole("button", { name: /scroll to top/i }),
    ).not.toBeInTheDocument();
  });

  test("calls window.scrollTo with top: 0 and smooth behavior on click", async () => {
    const user = userEvent.setup();
    render(<ScrollToTopButton defaultVisible={true} scrollYOffset={-1} />);

    const button = screen.getByRole("button", { name: /scroll to top/i });
    await user.click(button);

    expect(window.scrollTo).toHaveBeenCalledTimes(1);
    expect(window.scrollTo).toHaveBeenCalledWith({
      top: 0,
      behavior: "smooth",
    });
  });
});
