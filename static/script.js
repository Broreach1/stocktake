let cart = [];

async function loadProducts() {
  const res = await fetch("/api/products");
  const products = await res.json();
  const container = document.getElementById("products");
  container.innerHTML = "<h2>Products</h2>";
  products.forEach(p => {
    const div = document.createElement("div");
    div.innerHTML = `
      <b>${p.name}</b> - $${p.price} (Stock: ${p.stock})
      <button onclick="addToCart(${p.id}, '${p.name}', ${p.price})">Add</button>
    `;
    container.appendChild(div);
  });
}

function addToCart(id, name, price) {
  const existing = cart.find(i => i.id === id);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ id, name, price, qty: 1 });
  }
  renderCart();
}

function renderCart() {
  const ul = document.getElementById("cart");
  ul.innerHTML = "";
  cart.forEach(item => {
    const li = document.createElement("li");
    li.textContent = `${item.name} x${item.qty} = $${(item.qty * item.price).toFixed(2)}`;
    ul.appendChild(li);
  });
}

async function checkout() {
  if (cart.length === 0) {
    alert("Cart empty!");
    return;
  }
  const res = await fetch("/api/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cart })
  });
  const data = await res.json();
  if (data.status === "ok") {
    alert("Sale complete! ID: " + data.sale_id);
    cart = [];
    renderCart();
    loadProducts();
  } else {
    alert("Error: " + data.msg);
  }
}

window.onload = loadProducts;
