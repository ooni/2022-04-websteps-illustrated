//
// 1. make sure we can sort tables by clicking on their headers
//


// See https://developer.mozilla.org/en-US/docs/Web/HTML/Element/table

const allTables = document.querySelectorAll('table')

for (let table of allTables) {
  const tBody = table.tBodies[0]
  const rows = Array.from(tBody.rows)
  const headerCells = table.tHead.rows[0].cells

  for (let th of headerCells) {
    const cellIndex = th.cellIndex;

    th.addEventListener("click", () => {
      rows.sort((tr1, tr2) => {
        const tr1Text = tr1.cells[cellIndex].textContent
        const tr2Text = tr2.cells[cellIndex].textContent
        return tr1Text.localeCompare(tr2Text)
      })

      tBody.append(...rows)
    })
  }
}

//
// 2. manage the way in which we show/hide entries
//

let editingStack = []

// See https://stackoverflow.com/a/3369743
document.onkeydown = function (evt) {
  evt = evt || window.event;
  var isEscape = false;
  if ("key" in evt) {
    isEscape = (evt.key === "Escape" || evt.key === "Esc");
  } else {
    isEscape = (evt.keyCode === 27);
  }
  if (!isEscape) {
    return
  }
  if (editingStack.length <= 0) {
    return
  }
  let top = editingStack.pop()
  if (top === null) {
    // Special case: the user is editing details so we just need to
    // hide details and after that we're good
    let details = document.getElementsByClassName("details")
    for (let i = 0; i < details.length; i += 1) {
      let element = details[i]
      element.style.display = "none"
    }
    return
  }
  for (let i = 0; i < top.length; i += 1) {
    const cleanup = top[i]
    cleanup()
  }
}

// makeVisible changes the visibility of elements int the page ensuring
// that only specific elements have visibility.
function makeVisible(id) {

  // Check whether the user has clicked onto a row of the table that
  // contains the listing of all available test cases.
  if (id.startsWith("measurements-")) {
    let changed = []
    let visibles = document.getElementsByClassName("starts-visible")
    for (let i = 0; i < visibles.length; i += 1) {
      let element = visibles[i]
      const candidateID = id.replace(/^measurements-/, "summary-")
      if (element.id === candidateID) {
        element.style.display = "table-row"
      } else {
        element.style.display = "none"
        changed.push(function () {
          element.style.display = "table-row"
        })
      }
    }
    // The element with the given ID needs to become visibile and
    // we need to register to make it invisible later on
    let element = document.getElementById(id)
    if (element !== null) {
      element.style.display = "block"
      changed.push(function () {
        element.style.display = "none"
      })
    }
    if (changed.length > 0) {
      editingStack.push(changed)
    }
  }

  // Check whether the user has clicked onto a row of the table that
  // contains the listing of all available test cases.
  //
  // This kind of changes have no impact on the editing stack.
  if (id.startsWith("details-")) {
    let invisibles = document.getElementsByClassName("starts-hidden")
    for (let i = 0; i < invisibles.length; i += 1) {
      let element = invisibles[i]
      if (!element.id.startsWith("details-")) {
        continue
      }
      if (element.id !== id) {
        element.style.display = "none"
      } else {
        element.style.display = "block"
      }
    }
    // Use null as a sentinel value in the editing stack that basically implies
    // a leaf state where we just want to clear the details when the user
    // press Esc as opposed to creating a full editing history.
    if (editingStack.length > 0 && editingStack[editingStack.length - 1] !== null) {
      editingStack.push(null)
    }
  }
}
