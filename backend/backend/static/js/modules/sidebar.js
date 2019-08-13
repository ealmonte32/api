import SimpleBar from "simplebar"; // Usage: https://github.com/Grsmto/simplebar

$(function() {
  const simpleBarEnabled =
    document.getElementsByClassName("js-simplebar").length > 0;
  const simpleBarInstance = simpleBarEnabled
    ? new SimpleBar(document.getElementsByClassName("js-simplebar")[0])
    : null;

  /* Sidebar toggle behaviour */
  $(".sidebar-toggle").on("click", function() {
    $(".sidebar")
      .toggleClass("toggled")
      // Triger resize after animation
      .one("transitionend", function() {
        setTimeout(function() {
          window.dispatchEvent(new Event("resize"));
        }, 100);
      });
  });

  const active = $(".sidebar .active");

  if (active.length && active.parent(".collapse").length) {
    const parent = active.parent(".collapse");

    parent.prev("a").attr("aria-expanded", true);
    parent.addClass("show");
  }
});
