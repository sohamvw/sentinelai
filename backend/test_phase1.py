from app.services.phase1_tree_service import Phase1TreeService
import tempfile
import os

# Create a small test repo
with tempfile.TemporaryDirectory() as tmpdir:
    repo_path = os.path.join(tmpdir, 'test_repo')
    os.makedirs(repo_path)

    # Create test files
    with open(os.path.join(repo_path, 'main.py'), 'w') as f:
        f.write('def main():\n    print("hello")\n\nif __name__ == "__main__":\n    main()\n')

    with open(os.path.join(repo_path, 'config.yaml'), 'w') as f:
        f.write('debug: true\nport: 8000\n')

    with open(os.path.join(repo_path, 'requirements.txt'), 'w') as f:
        f.write('fastapi==0.109.0\nuvicorn==0.27.0\n')

    os.makedirs(os.path.join(repo_path, 'tests'))
    with open(os.path.join(repo_path, 'tests', 'test_main.py'), 'w') as f:
        f.write('def test_main():\n    assert True\n')

    # Run Phase 1
    workspace = os.path.join(tmpdir, 'workspace')
    os.makedirs(workspace)

    result = Phase1TreeService.build_tree(repo_path, workspace)

    print('SUCCESS: tree.json created')
    print(f'Total files: {result["scan_metadata"]["total_files"]}')
    print(f'Languages: {result["summary"]["languages"]}')
    print(f'Entry points: {result["summary"]["entry_points"]}')
    print(f'Config files: {result["summary"]["config_files"]}')
    print(f'Manifests: {result["summary"]["dependency_manifests"]}')
    print(f'Test files: {result["summary"]["test_files"]}')
    print(f'Docs files: {result["summary"]["docs_files"]}')

    # Verify file entries
    for f in result['files']:
        print(f'  {f["relative_path"]}: lang={f["language"]}, size={f["size"]}, sha256={f["sha256"][:16]}..., binary={f["is_binary"]}, entry={f["is_entry_point"]}, config={f["is_config"]}, manifest={f["is_dependency_manifest"]}, test={f["is_test"]}, docs={f["is_docs"]}')