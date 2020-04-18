using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using myop.Models;

namespace myop.Controllers
{
    public class TokensController : Controller
    {
        private readonly ApplicationDbContext _context;

        public TokensController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: Tokens
        public async Task<IActionResult> Index()
        {
            return View(await _context.Tokens.ToListAsync());
        }

        // GET: Tokens/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var token = await _context.Tokens
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (token == null)
            {
                return NotFound();
            }

            return View(token);
        }

        // GET: Tokens/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Tokens/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("UserId,AccessToken,RefreshToken,Scope,Iat")] Token token)
        {
            if (ModelState.IsValid)
            {
                _context.Add(token);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(token);
        }

        // GET: Tokens/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var token = await _context.Tokens.FindAsync(id);
            if (token == null)
            {
                return NotFound();
            }
            return View(token);
        }

        // POST: Tokens/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("UserId,AccessToken,RefreshToken,Scope,Iat")] Token token)
        {
            if (id != token.UserId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(token);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TokenExists(token.UserId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(token);
        }

        // GET: Tokens/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var token = await _context.Tokens
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (token == null)
            {
                return NotFound();
            }

            return View(token);
        }

        // POST: Tokens/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var token = await _context.Tokens.FindAsync(id);
            _context.Tokens.Remove(token);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TokenExists(string id)
        {
            return _context.Tokens.Any(e => e.UserId == id);
        }
    }
}
