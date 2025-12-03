#!/usr/bin/env python3
"""
Setup script for WinProc MCP
Automatically adds the MCP server configuration to Claude Code settings
"""

import json
import os
import sys
from pathlib import Path

def setup_mcp_server():
    """Add MCP server configuration to Claude Code settings"""
    
    print("WinProc MCP Setup")
    print("=" * 60)
    print()
    
    # Get the current script directory
    script_dir = Path(__file__).parent.absolute()
    mcp_server_path = script_dir / "winproc_mcp.py"
    
    print(f"🔍 Detected MCP server location: {script_dir}")
    print(f"🐍 Looking for: {mcp_server_path}")
    print()
    
    # Verify MCP server file exists
    if not mcp_server_path.exists():
        print(f"❌ Error: MCP server file not found at {mcp_server_path}")
        print()
        print("Available options:")
        print("1. Ensure winproc_mcp.py is in the same directory as this setup script")
        print("2. Run this setup script from the directory containing winproc_mcp.py")
        print("3. Specify a custom path when prompted")
        print()
        
        response = input("Would you like to specify a custom path to winproc_mcp.py? (y/N): ").lower().strip()
        if response in ['y', 'yes']:
            while True:
                custom_path = input("Enter the full path to winproc_mcp.py: ").strip()
                custom_path = Path(custom_path)
                
                if custom_path.exists() and custom_path.name == "winproc_mcp.py":
                    mcp_server_path = custom_path.absolute()
                    print(f"✅ Using custom path: {mcp_server_path}")
                    break
                else:
                    print(f"❌ File not found: {custom_path}")
                    retry = input("Try again? (y/N): ").lower().strip()
                    if retry not in ['y', 'yes']:
                        return False
        else:
            return False
    
    # Ask user to confirm the location
    print(f"📂 MCP Server files location: {mcp_server_path.parent}")
    print(f"🐍 MCP Server file: {mcp_server_path.name}")
    
    # Check for other required files
    admin_helper = mcp_server_path.parent / "admin_helper.ps1"
    requirements = mcp_server_path.parent / "requirements.txt"
    
    print()
    print("📋 Checking required files:")
    print(f"   winproc_mcp.py: {'✅' if mcp_server_path.exists() else '❌'}")
    print(f"   admin_helper.ps1:  {'✅' if admin_helper.exists() else '❌'}")
    print(f"   requirements.txt:  {'✅' if requirements.exists() else '❌'}")
    
    if not admin_helper.exists():
        print(f"⚠️  Warning: admin_helper.ps1 not found - UAC elevation may not work")
    
    print()
    confirm = input(f"Is {mcp_server_path.parent} where you have saved the WinProc MCP files? (Y/n): ").lower().strip()
    if confirm in ['n', 'no']:
        print("\nPlease specify the correct location.")
        while True:
            custom_dir = input("Enter the full path to the folder containing the MCP server files: ").strip()
            custom_dir = Path(custom_dir)
            
            if not custom_dir.exists():
                print(f"❌ Directory not found: {custom_dir}")
                retry = input("Try again? (y/N): ").lower().strip()
                if retry not in ['y', 'yes']:
                    print("Setup cancelled")
                    return False
                continue
            
            # Check for required files in the custom directory
            custom_mcp_server = custom_dir / "winproc_mcp.py"
            custom_admin_helper = custom_dir / "admin_helper.ps1"
            
            print(f"\n📋 Checking files in {custom_dir}:")
            print(f"   winproc_mcp.py: {'✅' if custom_mcp_server.exists() else '❌'}")
            print(f"   admin_helper.ps1:  {'✅' if custom_admin_helper.exists() else '❌'}")
            
            if not custom_mcp_server.exists():
                print(f"❌ Error: winproc_mcp.py not found in {custom_dir}")
                retry = input("Try a different directory? (y/N): ").lower().strip()
                if retry not in ['y', 'yes']:
                    print("Setup cancelled")
                    return False
                continue
            
            if not custom_admin_helper.exists():
                print(f"⚠️  Warning: admin_helper.ps1 not found - UAC elevation may not work")
            
            # Confirm this is the right directory
            use_this = input(f"\nUse {custom_dir} for the MCP server installation? (Y/n): ").lower().strip()
            if use_this not in ['n', 'no']:
                mcp_server_path = custom_mcp_server.absolute()
                print(f"✅ Using custom location: {mcp_server_path.parent}")
                break
            else:
                retry = input("Try a different directory? (y/N): ").lower().strip()
                if retry not in ['y', 'yes']:
                    print("Setup cancelled")
                    return False
    
    # Get Claude config file path
    config_path = Path.home() / ".claude.json"
    
    print(f"📁 Claude config file: {config_path}")
    print(f"🐍 MCP server path: {mcp_server_path}")
    print()
    
    # Read existing config or create new one
    config = {}
    config_exists = config_path.exists()
    
    if config_exists:
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print("✅ Found existing Claude configuration")
        except Exception as e:
            print(f"❌ Error reading existing config: {e}")
            print("Creating new configuration...")
            config = {}
    else:
        print("📝 No existing Claude configuration found - will create new one")
    
    # Ensure mcpServers section exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    
    # Check if our server is already configured
    server_name = "winproc_mcp"
    if server_name in config["mcpServers"]:
        print(f"⚠️  MCP server '{server_name}' is already configured")
        print(f"Current configuration: {json.dumps(config['mcpServers'][server_name], indent=2)}")
        print()
        
        response = input("Do you want to update it? (y/N): ").lower().strip()
        if response not in ['y', 'yes']:
            print("Setup cancelled - no changes made")
            return True
    
    # Add our MCP server configuration
    config["mcpServers"][server_name] = {
        "type": "stdio",
        "command": "python",
        "args": [str(mcp_server_path)],
        "env": {}
    }
    
    # Create backup if config exists
    if config_exists:
        backup_path = config_path.with_suffix('.json.backup')
        try:
            with open(backup_path, 'w', encoding='utf-8') as f:
                with open(config_path, 'r', encoding='utf-8') as original:
                    f.write(original.read())
            print(f"💾 Created backup: {backup_path}")
        except Exception as e:
            print(f"⚠️  Could not create backup: {e}")
    
    # Write updated configuration
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Successfully added MCP server configuration!")
        print()
        print("📋 Configuration added:")
        print(json.dumps({server_name: config["mcpServers"][server_name]}, indent=2))
        print()
        print("🔄 Next steps:")
        print("1. Restart Claude Code to load the new MCP server")
        print("2. Test with: 'Show me all listening ports'")
        print("3. For admin operations: 'Stop service SomeServiceName'")
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error writing configuration: {e}")
        return False

def check_dependencies():
    """Check if required Python packages are installed"""
    print("🔍 Checking Python dependencies...")
    
    try:
        import mcp
        print("✅ mcp package is installed")
    except ImportError:
        print("❌ mcp package not found")
        print("Run: pip install -r requirements.txt")
        return False
    
    try:
        import pydantic
        print("✅ pydantic package is installed")
    except ImportError:
        print("❌ pydantic package not found") 
        print("Run: pip install -r requirements.txt")
        return False
    
    return True

def check_powershell_policy():
    """Check PowerShell execution policy"""
    print("🔍 Checking PowerShell execution policy...")
    
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command", "Get-ExecutionPolicy"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            policy = result.stdout.strip()
            print(f"✅ PowerShell execution policy: {policy}")
            
            if policy in ["Restricted", "AllSigned"]:
                print("⚠️  Restrictive execution policy detected")
                print("You may need to run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser")
        else:
            print("⚠️  Could not check PowerShell execution policy")
            
    except Exception as e:
        print(f"⚠️  Error checking PowerShell: {e}")

def main():
    """Main setup function"""
    
    # Check if running on Windows
    if sys.platform != "win32":
        print("❌ This MCP server is designed for Windows only")
        return False
    
    print("Checking prerequisites...")
    print()
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Please install missing dependencies first:")
        print("pip install -r requirements.txt")
        return False
    
    # Check PowerShell policy
    check_powershell_policy()
    print()
    
    # Setup MCP server
    success = setup_mcp_server()
    
    if success:
        print("🎉 Setup completed successfully!")
        print()
        print("💡 Usage examples after restarting Claude Code:")
        print('   "Find processes for WindowsTestService"')
        print('   "What process is listening on port 80?"')
        print('   "Show me all listening ports"')
        print('   "Stop service SomeServiceName" (requires UAC)')
    else:
        print("❌ Setup failed - please check the errors above")
    
    return success

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)